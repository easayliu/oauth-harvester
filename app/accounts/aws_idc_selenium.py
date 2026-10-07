"""aws-kiro 浏览器路径的 Selenium 版（B2 全量港口）。

背景：AWS WAF 抓 Playwright 的 instrumentation，换 Selenium/WebDriver 驱动真浏览器
（chrome/safari）可过。本模块把 aws_idc.py 的「登 AWS 控制台 → IAM Identity Center
建 IDC 用户」整条 Playwright UI 流程用 Selenium 复刻。backend=chrome/safari 时
run_aws_kiro 走这里，而非 cloak_browser_session（camoufox/Playwright）。

纯逻辑（URL 构造 / 正则解析 / 用户名·密码生成）直接复用 aws_idc.py，不重写。
"""
import logging
import re
import time

from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys

from app.accounts.aws_idc import (
    gen_idc_user, gen_new_password, _parse_idc_login_info,
    _sso_users_url, _sso_dashboard_url, _sso_home_url,
    _INSTANCE_ID_RE, _PORTAL_URL_RE, _PORTAL_URL_APP_RE,
    _extract_otp_by_label, _looks_like_login_info,
)
from app.core.browser import generate_totp, screenshot_path
from app.kiro.safari_idc import _make_webdriver

logger = logging.getLogger(__name__)

_POLL = 0.25
_SETTLE_SCALE = 0.6


# ============================================================
# 通用 Selenium 原语（对齐 aws_idc.py 的 _click_first / _fill_field / _settle / _shot）
# ============================================================
def _settle(ms: int = 900):
    if ms > 0:
        time.sleep(max(0.2, ms * _SETTLE_SCALE / 1000.0))


def _shot(driver, name: str, admin: str = None):
    try:
        driver.save_screenshot(screenshot_path(name, admin))
    except Exception:
        pass


def _ve(el) -> bool:
    try:
        return el.is_displayed() and el.is_enabled()
    except Exception:
        return False


def _visible(el) -> bool:
    try:
        return el.is_displayed()
    except Exception:
        return False


def _T(tag: str, text: str):
    """tag:has-text(text) → XPath（text 不含引号，本流程文案均满足）。"""
    return (By.XPATH, f'//{tag}[contains(normalize-space(.),"{text}")]')


def _click_first(driver, specs, desc="", timeout_ms=8000) -> bool:
    """specs: [(By, value), ...]，点第一个可见可用的。timeout_ms=0 单遍。"""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while True:
        for by, val in specs:
            try:
                for el in driver.find_elements(by, val):
                    if _ve(el):
                        try:
                            el.click()
                            if desc:
                                logger.info(f"[aws-sel] 点击 {desc}")
                            return True
                        except Exception:
                            continue
            except Exception:
                continue
        if timeout_ms == 0 or time.monotonic() > deadline:
            return False
        time.sleep(_POLL)


def _robust_fill(el, value: str) -> bool:
    """填值并回读确认（Cloudscape 受控输入常吞普通 send_keys）。"""
    try:
        el.click()
    except Exception:
        pass
    try:
        el.clear()
        el.send_keys(value)
        if (el.get_attribute("value") or "") == value:
            return True
    except Exception:
        pass
    try:
        el.clear()
        for ch in value:
            el.send_keys(ch)
        return (el.get_attribute("value") or "") == value
    except Exception:
        return False


def _fill_field(driver, labels, value, fallback_css, desc, timeout_ms=8000) -> bool:
    """按 label 邻近 input 或 fallback CSS 填值。对齐 aws_idc._fill_field。"""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while True:
        for lab in labels:
            for xp in (f'//*[normalize-space(text())="{lab}"]/following::input[1]',
                       f'//label[starts-with(normalize-space(.),"{lab}")]/following::input[1]',
                       f'//*[normalize-space(text())="{lab}"]/following::textarea[1]'):
                try:
                    els = driver.find_elements(By.XPATH, xp)
                except Exception:
                    els = []
                if els and _ve(els[0]) and _robust_fill(els[0], value):
                    logger.info(f"[aws-sel] 填 {desc}")
                    return True
        for css in fallback_css:
            try:
                els = [e for e in driver.find_elements(By.CSS_SELECTOR, css) if _ve(e)]
            except Exception:
                els = []
            if els and _robust_fill(els[0], value):
                logger.info(f"[aws-sel] 填 {desc}（fallback）")
                return True
        if timeout_ms == 0 or time.monotonic() > deadline:
            logger.debug(f"[aws-sel] 未填到 {desc}")
            return False
        time.sleep(_POLL)


def _wait_url(driver, pattern: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if re.search(pattern, driver.current_url or ""):
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def _wait_visible(driver, spec, timeout_s: float, optional=False):
    by, val = spec
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            for el in driver.find_elements(by, val):
                if _visible(el):
                    return el
        except Exception:
            pass
        time.sleep(0.3)
    if not optional:
        logger.warning(f"[aws-sel] 等待元素超时: {val}")
    return None


def _any_visible(driver, specs) -> bool:
    for by, val in specs:
        try:
            for el in driver.find_elements(by, val):
                if _visible(el):
                    return True
        except Exception:
            continue
    return False


# ============================================================
# AWS Root 控制台登录（WAF 在这一步；Selenium 真浏览器过）
# ============================================================
def _dismiss_feedback(driver):
    try:
        _click_first(driver, [
            (By.XPATH, '//div[@role="dialog"][contains(.,"Feedback for AWS Sign-in")]'
                       '//button[contains(.,"Cancel")]'),
            (By.CSS_SELECTOR, 'div[role="dialog"] button[aria-label="Close"]'),
            (By.CSS_SELECTOR, 'div[role="dialog"] button[aria-label="close"]'),
        ], "", timeout_ms=0)
    except Exception:
        pass


def _wait_captcha(driver, stage="", timeout_s=180):
    """AWS 登录 CAPTCHA：出现则等人工手过（需 HEADLESS=False），最多 timeout_s。"""
    specs = [(By.CSS_SELECTOR,
              '#captcha_image, img[id*="captcha"], input#captchaGuess, input[name="captchaGuess"]')]
    if not _any_visible(driver, specs):
        return
    logger.warning(f"[aws-sel] 检测到登录 CAPTCHA（{stage}），等人工手过…（需 HEADLESS=False）")
    _shot(driver, f"aws_captcha_{stage}")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not _any_visible(driver, specs):
            logger.info("[aws-sel] CAPTCHA 已过")
            return
        time.sleep(2)


def aws_console_login(driver, email, password, totp_secret,
                      akid="", sak="", destination_url="") -> None:
    """Selenium 版 AWS Root 登录（email→password→MFA）。落到 destination_url。
    注：本 B2 港口只实现邮箱密码路径（用户选 B：无 AK/SK）；AK/SK 联邦登录未港口。"""
    driver.get(destination_url)
    _wait_url(driver, r"signin\.aws\.amazon\.com", 10)
    _settle(900)
    if "signin.aws.amazon.com" not in (driver.current_url or ""):
        logger.info("[aws-sel] 已是登录态，跳过登录")
        return
    _dismiss_feedback(driver)

    # 选 Root user
    _click_first(driver, [
        _T("label", "Root user"),
        _T("label", "根用户"),
        (By.CSS_SELECTOR, '#section_root_account_radio_button'),
        (By.CSS_SELECTOR, 'input[type="radio"][value="root"]'),
    ], "Root user 单选", timeout_ms=5000)
    _settle(500)

    # Email → Next
    email_el = _wait_visible(driver, (By.CSS_SELECTOR, '#resolving_input'), 15)
    if not email_el:
        raise RuntimeError("[aws-sel] 未见 email 输入框（登录页结构异常）")
    _robust_fill(email_el, email)
    _click_first(driver, [(By.CSS_SELECTOR, '#next_button')], "Next", timeout_ms=10000)
    _settle(900)
    _wait_captcha(driver, "after_email")
    _dismiss_feedback(driver)

    # Password → Sign in
    pwd_el = _wait_visible(driver, (By.CSS_SELECTOR, '#password'), 20)
    if not pwd_el:
        raise RuntimeError("[aws-sel] 未见 password 输入框")
    _robust_fill(pwd_el, password)
    _click_first(driver, [(By.CSS_SELECTOR, '#signin_button')], "Sign in", timeout_ms=10000)
    _settle(900)
    _shot(driver, "aws_step_1_after_password", email)
    if _any_visible(driver, [
            (By.CSS_SELECTOR, '#password_error'),
            (By.XPATH, '//div[contains(.,"password is incorrect")]'),
            (By.XPATH, '//div[contains(.,"密码不正确")]')]):
        raise RuntimeError("AWS Root 密码错误")
    _wait_captcha(driver, "after_password")
    _dismiss_feedback(driver)

    # MFA / TOTP
    mfa = _wait_visible(driver, (By.CSS_SELECTOR, '#mfaCode'), 15, optional=True)
    if mfa and totp_secret:
        code = generate_totp(totp_secret)
        logger.info(f"[aws-sel] 本地生成 TOTP: {code}")
        _robust_fill(mfa, code)
        if not _click_first(driver, [(By.CSS_SELECTOR, '#mfa_submit_button')], "MFA 提交", timeout_ms=3000):
            mfa.send_keys(Keys.ENTER)
        _settle(900)
        _shot(driver, "aws_step_2_after_mfa", email)

    if not _wait_url(driver, r"console\.aws\.amazon\.com", 90):
        logger.warning("[aws-sel] 登录后未在 90s 内落到 console，继续尝试后续步骤")


# ============================================================
# 探 instance_id / 读 portal URL
# ============================================================
def _resolve_instance_id(driver, region, default_id) -> str:
    if default_id:
        return default_id
    driver.get(_sso_home_url(region))
    _settle(700)
    for _ in range(20):
        m = _INSTANCE_ID_RE.search(driver.current_url or "")
        if m:
            return m.group(1)
        time.sleep(0.5)
    raise RuntimeError("[aws-sel] 未能从 URL 解析 IAM Identity Center instance_id")


def _read_portal_url(driver, region, instance_id, admin="") -> str:
    driver.get(_sso_dashboard_url(region, instance_id))
    _settle(700)
    _settle(0)
    _shot(driver, "idc_dashboard", admin)
    for _ in range(20):
        try:
            body = driver.execute_script("return document.body ? document.body.innerText : ''") or ""
        except Exception:
            body = ""
        m = _PORTAL_URL_RE.search(body) or _PORTAL_URL_APP_RE.search(body)
        if m:
            return m.group(0)
        time.sleep(0.5)
    logger.warning("[aws-sel] 未从 dashboard 抓到 portal URL")
    return ""


# ============================================================
# 建 IDC 用户（Add user 向导）
# ============================================================
_IDC_USERNAME_CSS = [
    'input[id*="userName" i]', 'input[name*="userName" i]',
    'input[id*="username" i]', 'input[name*="username" i]',
    'input[placeholder*="user name" i]', 'input[placeholder*="username" i]',
    'input[placeholder*="Enter username" i]',
]

# OTP 单选钮：JS 就近定位（对齐 aws_idc._IDC_OTP_JS）
_OTP_JS = r"""
const doClick = arguments[0];
const els = [...document.querySelectorAll('*')].filter(e =>
  e.children.length < 8 && e.offsetParent !== null &&
  /generate.*one.?time.*password/i.test(e.textContent || ''));
if (!els.length) return 'none';
let host = els[els.length - 1];
let radio = null;
for (let i = 0; i < 8 && host; i++) {
  radio = host.querySelector('input[type=radio],[role=radio]');
  if (radio) break;
  host = host.parentElement;
}
if (!radio) return 'none';
const checked = radio.tagName === 'INPUT'
  ? radio.checked : radio.getAttribute('aria-checked') === 'true';
if (doClick && !checked) { radio.click(); return 'clicked'; }
return checked ? 'checked' : 'unchecked';
"""


def _otp_state(driver, do_click=False) -> str:
    try:
        return driver.execute_script(_OTP_JS, do_click) or "none"
    except Exception:
        return "none"


def _ensure_otp(driver):
    st = _otp_state(driver, False)
    if st in ("checked", "none"):   # none=页面无此控件，非阻塞
        return
    for _ in range(3):
        _otp_state(driver, True)
        _settle(250)
        if _otp_state(driver, False) in ("checked", "none"):
            return


def _username_input(driver):
    for xp in ('//*[normalize-space(text())="Username"]/following::input[1]',
               '//label[starts-with(normalize-space(.),"Username")]/following::input[1]',
               '//*[normalize-space(text())="用户名"]/following::input[1]'):
        try:
            for el in driver.find_elements(By.XPATH, xp):
                if _ve(el):
                    return el
        except Exception:
            continue
    for css in _IDC_USERNAME_CSS:
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, css):
                if _ve(el):
                    return el
        except Exception:
            continue
    return None


def _ensure_username(driver, value) -> bool:
    el = _username_input(driver)
    if el is None:
        return False
    try:
        if (el.get_attribute("value") or "") == value:
            return True
    except Exception:
        pass
    return _robust_fill(el, value)


# 向导步骤标题（判断当前在哪一步）
_STEP_HEADINGS = {
    "details": ["指定用户详细信息", "Specify user details"],
    "groups": ["将用户添加到组", "添加用户到组", "Add user to groups"],
    "review": ["查看并添加用户", "Review and add user"],
}


def _heading_has(driver, text) -> bool:
    xp = (f'//h1[contains(normalize-space(.),"{text}")]'
          f' | //h2[contains(normalize-space(.),"{text}")]'
          f' | //*[@role="heading"][contains(normalize-space(.),"{text}")]')
    try:
        return any(_visible(e) for e in driver.find_elements(By.XPATH, xp))
    except Exception:
        return False


def _current_step(driver) -> str:
    for step in ("review", "groups", "details"):   # review 先判（回显 details 文案）
        if any(_heading_has(driver, t) for t in _STEP_HEADINGS[step]):
            return step
    return "unknown"


def _click_next(driver, timeout_ms=8000) -> bool:
    """点「下一步/Next」，但只点文本以 next/下一步 开头的（排除 'account-switch' 类含 next 的按钮）。"""
    deadline = time.monotonic() + timeout_ms / 1000.0
    while True:
        for by, val in [_T("button", "下一步"), _T("button", "Next")]:
            try:
                for el in driver.find_elements(by, val):
                    if not _ve(el):
                        continue
                    t = (el.text or "").strip().lower()
                    if t.startswith("next") or t.startswith("下一步"):
                        try:
                            el.click()
                            return True
                        except Exception:
                            continue
            except Exception:
                continue
        if time.monotonic() > deadline:
            return False
        time.sleep(_POLL)


def _advance_step(driver, target, admin) -> bool:
    for _ in range(4):
        if _current_step(driver) == target:
            return True
        _click_next(driver)
        end = time.monotonic() + 6
        while time.monotonic() < end:
            if _current_step(driver) == target:
                return True
            time.sleep(0.4)
        _settle(600)
    return _current_step(driver) == target


def _select_group(driver, group_name, admin):
    # 搜索框填组名
    for css in ['input[placeholder*="群组" i]', 'input[placeholder*="group" i]',
                'input[placeholder*="搜索" i]', 'input[placeholder*="Search" i]',
                'input[type="search"]']:
        els = [e for e in driver.find_elements(By.CSS_SELECTOR, css) if _ve(e)]
        if els and _robust_fill(els[0], group_name):
            break
    _settle(900)
    _click_first(driver, [
        (By.XPATH, f'//tr[contains(normalize-space(.),"{group_name}")]//input[@type="checkbox"]/..'),
        (By.XPATH, f'//tr[contains(normalize-space(.),"{group_name}")]//label'),
        (By.XPATH, f'//*[@role="row"][contains(normalize-space(.),"{group_name}")]//input[@type="checkbox"]/..'),
        (By.XPATH, f'//*[@role="row"][contains(normalize-space(.),"{group_name}")]//label'),
    ], f"选群组 {group_name}", timeout_ms=10000)
    _shot(driver, "idc_group_selected", admin)


def _submit_review(driver, admin) -> bool:
    submit_specs = [
        (By.CSS_SELECTOR, 'button[class*="variant-primary" i]'),
        _T("button", "完成"), _T("button", "Finish"),
        _T("button", "提交"), _T("button", "Submit"),
        _T("button", "添加用户"), _T("button", "Add user"),
    ]
    for attempt in range(3):
        if attempt == 0 and _current_step(driver) != "review":
            return False
        _click_first(driver, submit_specs, "提交建用户", timeout_ms=20000)
        # 判定是否生效：出现结果弹窗 / primary 按钮消失
        end = time.monotonic() + 8
        while time.monotonic() < end:
            try:
                dlgs = driver.find_elements(By.CSS_SELECTOR, 'div[role="dialog"]')
                for d in dlgs:
                    if _visible(d):
                        txt = (d.text or "").lower()
                        if any(s in txt for s in ("一次性密码", "one-time password", "复制", "copy")):
                            return True
            except Exception:
                pass
            time.sleep(0.5)
        _settle(1200)
    return True


def _capture_login_info(driver, admin) -> str:
    """点「复制/Copy」后优先读弹窗 DOM 文本（Selenium 下最稳），再兜底 clipboard。
    只接受含 portal/OTP 特征的 blob（_looks_like_login_info + 显式 OTP 标签）。"""
    _click_first(driver, [
        (By.XPATH, '//div[@role="dialog"]//button[contains(.,"复制")]'),
        (By.XPATH, '//div[@role="dialog"]//button[contains(.,"Copy")]'),
        _T("button", "复制"), _T("button", "Copy"),
    ], "复制登录信息", timeout_ms=8000)
    _settle(400)

    deadline = time.monotonic() + 45
    raw = ""
    while time.monotonic() < deadline:
        # 读弹窗 DOM 文本
        for css in ['div[role="dialog"]', '[role="alertdialog"]', '[class*="modal" i]']:
            try:
                for d in driver.find_elements(By.CSS_SELECTOR, css):
                    if not _visible(d):
                        continue
                    txt = (d.text or "").strip()
                    if _looks_like_login_info(txt) and _extract_otp_by_label(txt):
                        raw = txt
                        break
            except Exception:
                continue
            if raw:
                break
        if raw:
            break
        # 兜底：clipboard
        try:
            clip = (driver.execute_script("return navigator.clipboard.readText ? "
                                          "navigator.clipboard.readText() : ''") or "")
            if isinstance(clip, str) and _extract_otp_by_label(clip):
                raw = clip.strip()
                break
        except Exception:
            pass
        time.sleep(0.8)

    if not raw:
        # 最后：整页文本，但必须含显式 OTP 标签
        try:
            body = driver.execute_script("return document.body.innerText") or ""
            if _extract_otp_by_label(body):
                raw = body.strip()
        except Exception:
            pass

    if raw:
        _shot(driver, "idc_otp_captured", admin)
    else:
        logger.warning("[aws-sel] 未抓到登录信息 blob")
    # 关弹窗（非关键）
    _click_first(driver, [
        _T("button", "关闭"), _T("button", "Close"), _T("button", "完成"),
        (By.CSS_SELECTOR, 'div[role="dialog"] button[aria-label*="close" i]'),
    ], "", timeout_ms=2000)
    return raw


def _idc_create_user(driver, region, instance_id, user, admin, group_name="") -> str:
    driver.get(_sso_users_url(region, instance_id))
    _settle(700)
    _settle(0)
    _shot(driver, "idc_users_landing", admin)

    # 1) 进 Add user 向导
    _click_first(driver, [
        _T("button", "Add user"), _T("a", "Add user"),
        _T("button", "添加用户"), _T("a", "添加用户"),
        _T("button", "Add users"), _T("a", "Add users"),
    ], "Add user 入口", timeout_ms=20000)
    _shot(driver, "idc_add_user_step1", admin)

    # 2) 用户名
    _fill_field(driver, ["用户名", "Username", "User name"], user["username"],
                _IDC_USERNAME_CSS, "用户名", timeout_ms=15000)
    _settle(500)

    # 3) 选「生成一次性密码」
    _click_first(driver, [
        (By.XPATH, '//*[contains(normalize-space(.),"Generate a one-time password")]'),
        (By.XPATH, '//*[contains(normalize-space(.),"生成一个可以与此用户共享的一次性密码")]'),
        (By.XPATH, '//label[contains(normalize-space(.),"一次性密码")]'),
        (By.XPATH, '//*[@role="radio"][contains(normalize-space(.),"one-time password")]'),
        (By.CSS_SELECTOR, '[data-testid*="one-time" i]'),
        (By.CSS_SELECTOR, 'input[type="radio"][value*="ONE_TIME" i]'),
    ], "选一次性密码", timeout_ms=15000)
    _ensure_otp(driver)

    # 4) 邮箱 + 确认邮箱
    _fill_field(driver, ["电子邮箱", "电子邮件地址", "Email address", "Email"],
                user["email"], ['input[type="email"]'], "email 主")
    _fill_field(driver, ["确认邮件地址", "确认电子邮件地址", "确认电子邮件", "Confirm email", "Confirm"],
                user["email"], [], "email 确认")
    # 邮箱位置兜底
    email_inputs = [e for e in driver.find_elements(
        By.CSS_SELECTOR, 'input[type="email"], input[placeholder*="example.com" i]') if _ve(e)]
    if len(email_inputs) >= 2:
        if not (email_inputs[0].get_attribute("value") or ""):
            _robust_fill(email_inputs[0], user["email"])
        if not (email_inputs[1].get_attribute("value") or ""):
            _robust_fill(email_inputs[1], user["email"])

    # 5) 名字
    _fill_field(driver, ["名字", "First name"], user["first_name"],
                ['input[id*="firstName" i]', 'input[name*="firstName" i]',
                 'input[placeholder*="first name" i]'], "first name")
    _fill_field(driver, ["姓氏", "Last name"], user["last_name"],
                ['input[id*="lastName" i]', 'input[name*="lastName" i]',
                 'input[placeholder*="last name" i]'], "last name")
    _fill_field(driver, ["显示名称", "Display name"], user["display_name"],
                ['input[id*="displayName" i]', 'input[name*="displayName" i]'], "display name")
    _settle(500)

    # 6) 收敛：Cloudscape 重渲染会擦掉 username / 重置 OTP，提交前钉住
    for _ in range(3):
        u_ok = _ensure_username(driver, user["username"])
        _ensure_otp(driver)
        cur = _username_input(driver)
        u_still = cur is not None and (cur.get_attribute("value") or "") == user["username"]
        if u_ok and u_still and _otp_state(driver, False) in ("checked", "none"):
            break
        _settle(300)
    _shot(driver, "idc_add_user_filled", admin)

    # 7) details → groups（可选选组）
    _advance_step(driver, "groups", admin)
    _settle(600)
    _shot(driver, "idc_groups_step", admin)
    if group_name:
        _select_group(driver, group_name, admin)

    # 8) groups → review
    _advance_step(driver, "review", admin)
    _settle(600)
    _shot(driver, "idc_review_step", admin)

    # 9) 提交 + 抓登录信息
    _submit_review(driver, admin)
    _settle(800)
    _shot(driver, "idc_after_submit", admin)
    return _capture_login_info(driver, admin)


# ============================================================
# 对外入口（供 run_aws_kiro 的 Selenium 分支调用）
# ============================================================
def open_console_and_prepare(admin_email, admin_password, admin_totp,
                             akid, sak, region, instance_id, backend="chrome"):
    """建 driver + 登录 + 探 instance_id + 读 portal URL。返回 (driver, instance_id, start_url)。
    失败会关掉 driver 再 raise。"""
    driver = _make_webdriver(backend)
    try:
        driver.set_window_size(1440, 900)
        dest = (f"https://{region}.console.aws.amazon.com/singlesignon/home"
                f"?region={region}#/instances")
        aws_console_login(driver, admin_email, admin_password, admin_totp, akid, sak, dest)
        rid = _resolve_instance_id(driver, region, instance_id)
        start_url = _read_portal_url(driver, region, rid, admin_email)
        return driver, rid, start_url
    except Exception:
        try:
            driver.quit()
        except Exception:
            pass
        raise


def provision_idc_user(driver, admin_email, region, instance_id, start_url,
                       email_domain, username_prefix, group_name, username="") -> dict:
    """在已登录 driver 上建 1 个 IDC 用户，返回与 aws_idc.provision_idc_user_on_page 同形的 dict。"""
    user = gen_idc_user(username_prefix, email_domain, username)
    new_password = gen_new_password()
    logger.info(f"[aws-sel] 建 IDC 用户: username={user['username']} email={user['email']}")
    login_info = _idc_create_user(driver, region, instance_id, user, admin_email, group_name)
    parsed = _parse_idc_login_info(login_info, username=user["username"])
    otp = parsed["one_time_password"]
    su = parsed["start_url"] or start_url
    idc_line = ""
    if su and otp:
        idc_line = f"idc::{su}----{user['username']}----{otp}----{new_password}"
    return {
        "username": user["username"], "email": user["email"], "start_url": su,
        "one_time_password": otp, "new_password": new_password,
        "login_info": login_info, "group": group_name, "idc_line": idc_line, "error": "",
    }


def close_driver(driver):
    try:
        driver.quit()
    except Exception:
        pass
