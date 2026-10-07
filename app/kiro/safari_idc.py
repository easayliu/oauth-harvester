"""用 Selenium/WebDriver 驱动真浏览器过 AWS WAF "Security check"。

实测结论：AWS WAF 抓的是 **Playwright 的自动化 instrumentation**（camoufox/cloak/webkit/
Playwright-真Chrome 全被拦），换 Selenium/WebDriver 驱动的真浏览器就放行。

支持两种 WebDriver 后端（driver 由 backend 决定，其余流程通用）：
  - safari : 真 Safari via safaridriver —— 仅 macOS；单会话（批量须串行）；需
             `sudo safaridriver --enable`
  - chrome : 真 Chrome via ChromeDriver —— 跨平台；可并发（多实例独立）；navigator.
             webdriver=False（去自动化标记）；实测同样过 WAF，推荐

两个入口：
  - drive_safari_idc_login : kiro 模式（register_kiro_idc 的 kiro-cli device flow）
  - drive_safari_apikey    : kiro-apikey 模式（register_kiro_apikey 的 kiro.dev 网页建 key）

Selenium 是同步 API，调用方用 asyncio.to_thread 包起来。
"""
import logging
import re
import subprocess
import time
from urllib.parse import urlsplit

from app.kiro.api import _idc_instance_region_from_url
from app.settings import PROXY

logger = logging.getLogger(__name__)


def _make_webdriver(backend: str = "safari"):
    """按 backend 造 Selenium WebDriver：chrome=真 Chrome（去自动化标记）/ safari=真 Safari。"""
    from selenium import webdriver
    if backend == "chrome":
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        opts.add_argument("--start-maximized")
        opts.add_argument("--no-first-run")
        opts.add_argument("--no-default-browser-check")
        opts.add_experimental_option("excludeSwitches", ["enable-automation"])
        opts.add_experimental_option("useAutomationExtension", False)
        opts.add_argument("--disable-blink-features=AutomationControlled")
        if PROXY:
            # 简单代理（无认证）：--proxy-server=host:port。带认证的代理 ChromeDriver
            # 需扩展注入，这里不处理——建议 safari/chrome 实测先用本机 IP。
            from urllib.parse import urlsplit as _u
            pu = _u(PROXY)
            if pu.hostname and not pu.username:
                scheme = pu.scheme or "http"
                port = f":{pu.port}" if pu.port else ""
                opts.add_argument(f"--proxy-server={scheme}://{pu.hostname}{port}")
            elif pu.username:
                logger.warning("[chrome] 检测到带认证的代理，ChromeDriver 简单模式不支持，本次忽略代理")
        return webdriver.Chrome(options=opts)
    from selenium.webdriver.safari.options import Options as SafariOptions
    return webdriver.Safari(options=SafariOptions())


def _kill_stray_automation():
    """杀掉残留的 `Safari --automation` 窗口（上一个账号会话失效后 quit() 没清掉的），
    否则 safaridriver 起不了新会话（'Allow remote automation' 报错）。串行模式下安全：
    开新会话前本不该有活跃自动化窗口。"""
    try:
        subprocess.run(["pkill", "-f", "Safari.*--automation"],
                       capture_output=True, timeout=10)
        time.sleep(1)
    except Exception as e:
        logger.debug(f"[safari] 清残留 automation 进程异常（忽略）: {e}")


def _reset_state(driver, urls):
    """逐域名清 cookie + localStorage/sessionStorage，隔离上一个账号的登录态。
    safaridriver 跨会话复用同一 Safari profile，不清会串号 / 表单状态错乱。"""
    for u in urls:
        try:
            driver.get(u)
            time.sleep(1)
            driver.delete_all_cookies()
            driver.execute_script("try{localStorage.clear();sessionStorage.clear();}catch(e){}")
        except Exception as e:
            logger.debug(f"[safari] 清 {u} 状态异常（忽略）: {e}")


def _aws_domains(start_or_verify_url, region):
    """本次登录会触及的、需清 cookie 的域名。"""
    doms = ["https://app.kiro.dev/"]
    try:
        netloc = urlsplit(start_or_verify_url).netloc
        if netloc:
            doms.append(f"https://{netloc}/")
    except Exception:
        pass
    doms.append(f"https://{region or 'us-east-1'}.signin.aws/")
    return doms

# AWS IdC 登录页按钮文案
_DEVICE_CONFIRM_TEXTS = ("Confirm and continue", "确认并继续", "Confirm", "确认")
_ALLOW_TEXTS = ("Allow access", "Allow", "允许访问", "允许", "Approve", "Accept", "批准", "接受")
_SKIP_MFA_TEXTS = ("Skip", "跳过", "Remind me later", "以后再说", "Not now")
_NEXT_TEXTS = ("下一步", "Next", "Continue", "继续")
_SIGNIN_TEXTS = ("登录", "Sign in", "下一步", "Next", "Continue")
_SETPWD_TEXTS = ("设置新密码", "Set new password", "Change password", "Update password",
                 "确认", "Confirm", "Submit")

# kiro.dev SPA 建 key 文案
_APIKEY_ENTRY_TEXTS = ("Create API key", "Create API Key", "Create new API key",
                       "Create new key", "New API key", "Add API key", "Generate API key",
                       "创建 API 密钥", "创建 API Key", "新建 API 密钥", "生成 API 密钥",
                       "Create key", "Create", "New key", "New", "创建密钥", "新建", "创建")
_APIKEY_CONFIRM_TEXTS = ("Create key", "Create API key", "Create", "Generate",
                         "Confirm", "Save", "Add", "确认创建", "创建", "生成", "确定", "保存")
_IDC_SWITCH_TEXTS = ("Sign in via IAM Identity Center instead",
                     "Sign in with IAM Identity Center instead",
                     "Sign in via IAM Identity Center", "IAM Identity Center instead",
                     "IAM Identity Center", "改用 IAM 身份中心", "使用 IAM 身份中心登录")

_KSK_RE = re.compile(r"ksk_[A-Za-z0-9_\-]{6,}")


# ============================================================
# 通用小工具
# ============================================================
def _click_by_text(driver, texts):
    """扫可见 button/[role=button]/a/input[submit]，文本命中就点，返回命中文本。"""
    from selenium.webdriver.common.by import By
    for el in driver.find_elements(By.CSS_SELECTOR,
                                   "button, [role=button], a, input[type=submit]"):
        try:
            if not el.is_displayed():
                continue
            label = (el.text or el.get_attribute("value") or "").strip()
            if label and any(t == label or t in label for t in texts):
                el.click()
                return label
        except Exception:
            continue
    return ""


def _fill(driver, el, value):
    try:
        el.click()
        el.clear()
    except Exception:
        pass
    el.send_keys(value)


def _react_fill(driver, el, value):
    """React 受控输入框安全填值：native setter + _valueTracker 复位 + input/change 事件，
    否则 React state 不更新、Continue 校验为空不跳转（kiro.dev 的 Start URL/Region 受控）。
    setter 路径没落值就退回真实键盘 send_keys。"""
    ok = driver.execute_script(
        """
        const el = arguments[0], v = arguments[1];
        try {
          const setter = Object.getOwnPropertyDescriptor(
            HTMLInputElement.prototype, 'value').set;
          const prev = el.value;
          el.focus();
          setter.call(el, v);
          if (el._valueTracker) el._valueTracker.setValue(prev);
          el.dispatchEvent(new Event('input', {bubbles: true}));
          el.dispatchEvent(new Event('change', {bubbles: true}));
          return el.value === v;
        } catch (e) { return false; }
        """, el, value)
    if not ok:
        _fill(driver, el, value)


def _visible(driver, css):
    from selenium.webdriver.common.by import By
    return [e for e in driver.find_elements(By.CSS_SELECTOR, css) if _is_disp(e)]


def _is_disp(el):
    try:
        return el.is_displayed()
    except Exception:
        return False


def _waf_present(driver):
    try:
        body = (driver.execute_script(
            "return document.body ? document.body.innerText : ''") or "").lower()
        if any(s in body for s in ("security check", "security challenge", "start your security")):
            return True
        return bool(driver.execute_script(
            "return !!document.querySelector('script[src*=\"awswaf\"],"
            " iframe[src*=\"awswaf\"], [id*=\"awswaf\"], #captcha-container, #captcha-box')"))
    except Exception:
        return False


def _capture_region(driver, box):
    if box.get("region"):
        return
    urls = []
    try:
        urls.append(driver.current_url)
    except Exception:
        pass
    try:
        urls += driver.execute_script(
            "return performance.getEntriesByType('resource').map(e => e.name)") or []
    except Exception:
        pass
    for u in urls:
        r = _idc_instance_region_from_url(u or "")
        if r:
            box["region"] = r
            logger.info(f"[safari] 捕获实例 region={r}（来源 {str(u)[:90]}）")
            return


# ============================================================
# AWS IdC 登录状态机：一次调用推进一步（用户名→临时密码→改密→Allow）
# ============================================================
def _aws_login_tick(driver, username, temp_pwd, new_pwd, state) -> bool:
    """按当前页面状态推进 AWS IdC 登录一步，返回是否有动作。
    state: {"user":bool, "temp":bool, "new":bool} 记录已完成的步骤，避免重复填。"""
    text_inputs = _visible(driver, "input[type=text], input[type=email]")
    pwd_inputs = _visible(driver, "input[type=password]")

    # 设置新密码页：两个密码框都填 new_pwd
    if len(pwd_inputs) >= 2 and not state["new"]:
        _fill(driver, pwd_inputs[0], new_pwd)
        _fill(driver, pwd_inputs[1], new_pwd)
        state["new"] = True
        hit = _click_by_text(driver, _SETPWD_TEXTS)
        logger.info(f"[safari] 填新密码并提交（按钮 '{hit or '默认'}'）")
        return True

    # 用户名页
    if text_inputs and not pwd_inputs and not state["user"]:
        _fill(driver, text_inputs[0], username)
        state["user"] = True
        hit = _click_by_text(driver, _NEXT_TEXTS)
        logger.info(f"[safari] 填用户名 {username} 并提交（按钮 '{hit or '默认'}'）")
        return True

    # 登录密码页（单个密码框）：先试临时密码
    if len(pwd_inputs) == 1 and not state["temp"]:
        _fill(driver, pwd_inputs[0], temp_pwd)
        state["temp"] = True
        state["temp_ts"] = time.time()
        hit = _click_by_text(driver, _SIGNIN_TEXTS)
        logger.info(f"[safari] 填临时密码并提交（按钮 '{hit or '默认'}'）")
        return True

    # 临时密码没过、8s 后仍停在密码页 → 账号可能已改过密，改用 new_pwd 重试
    if (len(pwd_inputs) == 1 and state["temp"] and not state.get("temp2")
            and time.time() - state.get("temp_ts", 0) > 8):
        _fill(driver, pwd_inputs[0], new_pwd)
        state["temp2"] = True
        hit = _click_by_text(driver, _SIGNIN_TEXTS)
        logger.info(f"[safari] 临时密码未过，改用 new_pwd 重试登录（按钮 '{hit or '默认'}'）")
        return True

    # 无输入框：设备确认 / Allow 授权 / 跳过 MFA
    if not text_inputs and not pwd_inputs:
        hit = (_click_by_text(driver, _ALLOW_TEXTS)
               or _click_by_text(driver, _DEVICE_CONFIRM_TEXTS)
               or _click_by_text(driver, _SKIP_MFA_TEXTS))
        if hit:
            logger.info(f"[safari] 点击按钮 '{hit}'")
            return True
    return False


# ============================================================
# 入口1：kiro 模式（device flow，token 落 kiro-cli sqlite）
# ============================================================
def drive_safari_idc_login(verify_url, username, temp_pwd, new_pwd,
                           is_done=None, timeout_s=180, backend="safari") -> str:
    """真浏览器（Selenium）走完 device flow 的 IdC 授权（用户名→临时密码→按需改密→Allow）。
    backend: safari / chrome。is_done: 无参回调，True 表示 kiro-cli 已拿到 token。
    返回捕获的实例 region（或 ""）。"""
    region_box = {"region": ""}
    state = {"user": False, "temp": False, "new": False}
    if backend == "safari":
        _kill_stray_automation()
    driver = _make_webdriver(backend)
    try:
        driver.set_window_size(1440, 900)
        # 隔离上一个账号的登录态（safaridriver 复用同一 Safari profile）
        _reset_state(driver, _aws_domains(verify_url, ""))
        logger.info(f"[safari] 打开 verify URL: {verify_url[:100]}")
        driver.get(verify_url)
        time.sleep(4)
        deadline = time.time() + timeout_s
        last_log = 0.0
        while time.time() < deadline:
            if is_done and is_done():
                logger.info("[safari] kiro-cli 已写入 token，登录成功")
                _capture_region(driver, region_box)
                return region_box["region"]
            _capture_region(driver, region_box)
            if _waf_present(driver):
                logger.warning("[safari] 出现 AWS WAF（真 Safari 罕见），等待…")
                time.sleep(3)
                continue
            _aws_login_tick(driver, username, temp_pwd, new_pwd, state)
            now = time.time()
            if now - last_log >= 15:
                last_log = now
                try:
                    logger.info(f"[safari] 进行中 url={driver.current_url[:110]}")
                except Exception:
                    pass
            time.sleep(2)
        if is_done and is_done():
            _capture_region(driver, region_box)
            return region_box["region"]
        try:
            driver.save_screenshot("scratch_safari_idc_timeout.png")
        except Exception:
            pass
        raise RuntimeError("[safari] IdC 登录超时未拿到 token（截图 scratch_safari_idc_timeout.png）")
    finally:
        try:
            driver.quit()
        except Exception:
            pass
        if backend == "safari":
            _kill_stray_automation()  # safari 会话若失效 quit 关不掉窗口，兜底清掉


# ============================================================
# 入口2：kiro-apikey 模式（kiro.dev 网页建 key）
# ============================================================
def _kiro_logged_in(driver) -> bool:
    """URL 在 app.kiro.dev 且不在 /signin，且页面不是 signin 选择页。"""
    try:
        u = driver.current_url or ""
    except Exception:
        return False
    if "app.kiro.dev" not in u or "/signin" in u:
        return False
    return not _kiro_is_signin_chooser(driver)


def _kiro_is_signin_chooser(driver) -> bool:
    """当前是否 kiro.dev signin 选择页（会话失效时 URL 不变但就地渲染）。"""
    try:
        if _click_probe(driver, "Your organization"):
            return True
        body = (driver.execute_script(
            "return document.body ? document.body.innerText : ''") or "").lower()
        return ("choose a way to sign" in body
                or ("builder id" in body and "your organization" in body))
    except Exception:
        return False


def _kiro_failed_to_load(driver) -> bool:
    """当前是否是 kiro.dev 'Kiro failed to load' 资源加载失败页（assets 被墙/加载失败，
    SPA 崩成 ErrorBoundary，表单整个消失）。"""
    try:
        low = (driver.execute_script(
            "return document.body ? document.body.innerText : ''") or "").lower()
    except Exception:
        return False
    return "kiro failed to load" in low or "assets.app.kiro.dev" in low


def _recover_failed_to_load(driver, tries=3) -> bool:
    """命中 'Kiro failed to load' 就点 Retry / 整页 reload 恢复。返回 True=已不在失败页。"""
    for _ in range(tries):
        if not _kiro_failed_to_load(driver):
            return True
        logger.warning("[safari] 命中 'Kiro failed to load' 资源加载失败页，尝试 Retry/reload 恢复")
        if not _click_by_text(driver, ("Retry", "重试", "Try again", "Reload", "重新加载")):
            try:
                driver.refresh()
            except Exception:
                pass
        time.sleep(4)
    return not _kiro_failed_to_load(driver)


def _click_probe(driver, text) -> bool:
    """页面是否存在含 text 的可见 button/a（只探测不点）。"""
    from selenium.webdriver.common.by import By
    for el in driver.find_elements(By.CSS_SELECTOR, "button, a, [role=button]"):
        try:
            if el.is_displayed() and text in (el.text or ""):
                return True
        except Exception:
            continue
    return False


# 严格的建 key 入口文案（用于判定"是否在 api-keys 页"，不含 Create/New 泛词，
# 否则主页的 "New session" 会被误判成 api-keys 页）
_APIKEY_STRICT_ENTRY = ("Create API key", "Create API Key", "Create new API key",
                        "New API key", "Add API key", "Generate API key",
                        "创建 API 密钥", "创建 API Key", "新建 API 密钥", "生成 API 密钥")


def _click_probe_any(driver, texts) -> bool:
    from selenium.webdriver.common.by import By
    for el in driver.find_elements(By.CSS_SELECTOR, "button, a, [role=button]"):
        try:
            if el.is_displayed():
                t = (el.text or "").strip()
                if t and any(x == t or x in t for x in texts):
                    return True
        except Exception:
            continue
    return False


def _on_apikeys_page(driver) -> bool:
    """当前是否真的落在 API keys 页（区分被弹回主页 'What can I help' / signin）。"""
    try:
        url = driver.current_url or ""
    except Exception:
        return False
    if "/signin" in url:
        return False
    try:
        low = (driver.execute_script(
            "return document.body ? document.body.innerText : ''") or "").lower()
    except Exception:
        low = ""
    if "what can i help" in low:  # Kiro 主页
        return False
    if _click_probe_any(driver, _APIKEY_STRICT_ENTRY):
        return True
    return "api key" in low and ("create" in low or "创建" in low or "生成" in low)


def _safari_goto_apikeys(driver, tries=5) -> bool:
    """重试深链进 api-keys 页并确认真的落在那（已登录态下深链偶发被弹主页）。"""
    for _ in range(tries):
        try:
            driver.get("https://app.kiro.dev/settings/api-keys")
        except Exception:
            pass
        for _ in range(8):
            time.sleep(1)
            _recover_failed_to_load(driver)  # 资源加载崩了先恢复再判定
            if _on_apikeys_page(driver):
                return True
            if "/signin" in (driver.current_url or ""):
                return False
    return False


def _extract_ksk(driver) -> str:
    """从当前页抓完整 ksk_（弹窗只显示一次）：input/textarea value、code/pre、body 兜底；
    紧跟 . 或 … 的掩码丢弃；取 len>=20 的最长。"""
    cands = driver.execute_script(
        r"""
        const re = /ksk_[A-Za-z0-9_\-]{6,}/g;
        const out = [];
        const push = (s) => { if(!s) return; let m; re.lastIndex=0;
          while((m=re.exec(s))!==null){ const tok=m[0];
            const after=s.slice(m.index+tok.length, m.index+tok.length+3);
            const trunc = after.indexOf('.')===0 || after.indexOf('…')===0;
            out.push({tok, trunc}); } };
        document.querySelectorAll('input,textarea').forEach(e=>push(e.value||''));
        document.querySelectorAll('code,pre').forEach(e=>push(e.innerText||e.textContent||''));
        push(document.body?document.body.innerText:'');
        return out;
        """) or []
    best = ""
    for c in cands:
        tok = c.get("tok") or ""
        if c.get("trunc") or len(tok) < 20:
            continue
        if len(tok) > len(best):
            best = tok
    return best


def _dump_labels(driver, tag):
    try:
        labels = driver.execute_script(
            "return [...document.querySelectorAll('button,a,[role=button]')]"
            ".filter(e=>e.offsetWidth||e.offsetHeight).slice(0,30)"
            ".map(e=>(e.innerText||'').trim()).filter(Boolean);")
        logger.warning(f"[safari] {tag}，页面可点按钮: {labels}")
    except Exception:
        logger.warning(f"[safari] {tag}")


def _click_in_scope(driver, scope_css, texts) -> str:
    """在 scope_css 作用域内点文本命中的按钮（scope_css 空串=全页）。返回命中文本。"""
    from selenium.webdriver.common.by import By
    sel = (scope_css + " " if scope_css else "") + "button, " + \
          (scope_css + " " if scope_css else "") + "[role=button]"
    for el in driver.find_elements(By.CSS_SELECTOR, sel):
        try:
            if not el.is_displayed():
                continue
            label = (el.text or "").strip()
            if label and any(t == label or t in label for t in texts):
                el.click()
                return label
        except Exception:
            continue
    return ""


def _close_popups(driver):
    """关掉 api-keys 页上的横幅/弹窗（Network configuration settings 提示、欢迎框等），
    否则可能挡住建 key 入口。点 Dismiss/Close/知道了 或 aria-label 含 close 的 X。"""
    for _ in range(4):
        hit = _click_by_text(driver, ("Dismiss", "Got it", "关闭", "知道了", "Close",
                                      "OK", "Skip", "跳过"))
        if not hit:
            try:
                hit = driver.execute_script("""
                    const b=[...document.querySelectorAll('button,[role=button]')].find(e=>
                      (e.offsetWidth||e.offsetHeight) &&
                      /close|dismiss|关闭|✕|×/i.test((e.getAttribute('aria-label')||'')
                        +(e.title||'')+(e.innerText||'')));
                    if(b){b.click(); return true;} return false;""")
            except Exception:
                hit = False
        if not hit:
            break
        time.sleep(0.5)


def _click_apikey_entry(driver) -> str:
    """找并点「建 key」入口。要求含 'key' + 创建类动词（'Create key'/'Create API key' 等），
    避开侧边栏 'New session'（无 key）与标题 'API Keys'（无动词）。返回命中文本（空=没找到）。"""
    try:
        return driver.execute_script(r"""
            const mk=/(create|generate|创建|生成|new|add|新建|添加)/i;
            const els=[...document.querySelectorAll('button,a,[role=button]')]
              .filter(e=>e.offsetWidth||e.offsetHeight);
            const label=e=>((e.innerText||'')+' '+(e.getAttribute('aria-label')||'')).toLowerCase();
            // pass1: 精确 create/generate + key（最稳，命中 'Create key' / 'Create API key'）
            for(const e of els){ const t=label(e);
              if(/(create|generate|创建|生成)/.test(t) && t.includes('key')){
                e.click(); return (e.innerText||'').trim().slice(0,40)||'(create key)'; } }
            // pass2: 'api key' + 任意 mk 动词
            for(const e of els){ const t=label(e);
              if(t.includes('api key') && mk.test(t)){
                e.click(); return (e.innerText||'').trim().slice(0,40)||'(api key btn)'; } }
            return '';
        """) or ""
    except Exception:
        return ""


def _safari_create_apikey(driver, key_name) -> str:
    """在 app.kiro.dev/settings/api-keys 点建 key → 等弹窗 → 填名 → 确认 → 抓 ksk_。
    出错必截图 scratch_safari_apikey_dialog.png，便于对着真实弹窗调选择器。"""
    # 0) 先关掉页面上的横幅/弹窗（否则可能挡住入口）
    _close_popups(driver)
    time.sleep(1)
    # 1) 严格找「含 api key + 动词」的入口（绝不点 New session / 聊天框）
    entry = _click_apikey_entry(driver)
    if not entry:
        _dump_labels(driver, "未找到建 API key 入口按钮（严格匹配 'api key'+动词）")
        try:
            driver.save_screenshot("scratch_safari_apikey_dialog.png")
        except Exception:
            pass
        return ""
    logger.info(f"[safari] 点开建 key 入口 '{entry}'")

    # 2) 轮询等弹窗/命名框出现（最多 ~15s，建 key 弹窗有渲染/网络延迟）
    name_inp = None
    for _ in range(30):
        time.sleep(0.5)
        cand = [c for c in _visible(
            driver, '[role=dialog] input, [role=alertdialog] input, '
                    'input[placeholder*="name" i], input[aria-label*="name" i], '
                    'input[id*="name" i]')
                if (c.get_attribute("type") or "text") != "password"]
        if cand:
            name_inp = cand[0]
            break
        # 弹窗已出但无命名框（有的 UI 无命名步）→ 停止等待去确认
        if _visible(driver, '[role=dialog], [role=alertdialog]'):
            break
    try:
        driver.save_screenshot("scratch_safari_apikey_dialog.png")
    except Exception:
        pass

    # 3) 填 Key name
    if name_inp:
        _react_fill(driver, name_inp, key_name)
        logger.info(f"[safari] 已填 Key name={key_name}")
        time.sleep(1)
    else:
        logger.info("[safari] 未见 Key name 输入框（该 UI 可能无需命名，直接确认）")

    # 4) 点确认 Create：优先弹窗/modal 内的 create/generate；兜底须同时含
    #    create/generate + key/api（绝不点到聊天框示例或侧边栏）
    confirm = ""
    try:
        confirm = driver.execute_script(r"""
            const els=[...document.querySelectorAll('button,[role=button]')]
              .filter(e=>e.offsetWidth||e.offsetHeight);
            const inDlg=e=>e.closest('[role=dialog],[role=alertdialog],'
              +'[class*=modal i],[class*=dialog i],[class*=popover i]');
            for(const e of els){ const t=(e.innerText||'').toLowerCase().trim();
              if(inDlg(e) && /(create|generate|confirm|确认|创建|生成|保存|save)/.test(t)){
                e.click(); return (e.innerText||'').trim().slice(0,40)||'(dlg create)'; } }
            for(const e of els){ const t=(e.innerText||'').toLowerCase();
              if(/(create|generate|创建|生成)/.test(t) && /(key|api|密钥)/.test(t)){
                e.click(); return (e.innerText||'').trim().slice(0,40)||'(create key)'; } }
            return '';
        """) or ""
    except Exception:
        confirm = ""
    if confirm:
        logger.info(f"[safari] 点确认建 key '{confirm}'")
    else:
        _dump_labels(driver, "未找到确认 Create 按钮")

    # 5) 抓 ksk_（key 生成有网络延迟，最多 ~20s 轮询）
    for _ in range(40):
        try:
            key = _extract_ksk(driver)
        except Exception as e:
            logger.debug(f"[safari] 抓 ksk 异常（重试）: {e}")
            key = ""
        if key:
            logger.info(f"[safari] 网页建 key 成功 ksk_…（len={len(key)}）")
            return key
        time.sleep(0.5)
    return ""


def drive_safari_apikey(start_url, username, temp_pwd, new_pwd, region,
                        key_name, timeout_s=300, backend="safari") -> dict:
    """真浏览器（Selenium）走完 kiro.dev 网页建 key：登录（过 WAF）→ /settings/api-keys → 建 key。
    backend: safari / chrome。返回 {"apiKey": ksk_..., "region": 捕获区}。失败 raise。"""
    region_box = {"region": ""}
    if backend == "safari":
        _kill_stray_automation()
    driver = _make_webdriver(backend)
    try:
        driver.set_window_size(1440, 900)
        deadline = time.time() + timeout_s
        # 隔离上一个账号的登录态：清 kiro.dev / awsapps / signin.aws 的 cookie+storage
        _reset_state(driver, _aws_domains(start_url, region))

        # ---- 确保登录 ----
        logged_in = False
        for _round in range(3):
            logger.info(f"[safari-apikey] 第 {_round + 1} 轮：进 api-keys 检查登录态")
            driver.get("https://app.kiro.dev/settings/api-keys")
            time.sleep(4)
            _recover_failed_to_load(driver)  # kiro.dev 资源加载崩了先恢复
            if _on_apikeys_page(driver):
                logger.info("[safari-apikey] 已登录，直达 api-keys")
                logged_in = True
                break

            # 未登录 → 此时已被 /settings/api-keys 重定向到
            # /signin?redirect_to_after_auth=%2Fsettings%2Fapi-keys（选择页）。
            # 关键：不要再 driver.get("/signin") —— 那会丢掉 redirect_to_after_auth，
            # 登录完就落到主页而非 api-keys 页（本 bug 根因）。就地在当前选择页操作。
            logger.info("[safari-apikey] 未登录，就地走 IDC 网页登录（保留 redirect_to_after_auth）")
            time.sleep(2)
            _recover_failed_to_load(driver)
            _click_by_text(driver, ("Your organization", "你的组织", "组织"))
            time.sleep(2)
            _click_by_text(driver, _IDC_SWITCH_TEXTS)

            # 轮询等 Start URL 框渲染（最多 ~18s）：kiro.dev SPA 偶发 'Kiro failed to load'
            # 导致表单不出（url_inputs=0）；路上恢复失败页 + 重点 IAM 切换。
            url_sel = ('input[type=url], input[name="startUrl"], input[id="startUrl"], '
                       'input[placeholder*="start" i], input[placeholder*="https" i], '
                       'input[aria-label*="URL" i]')
            reg_sel = ('input[name*="region" i], input[id*="region" i], '
                       'input[aria-label*="region" i], input[placeholder*="region" i], '
                       'input[placeholder*="us-east-1" i]')
            url_inp = []
            for _ in range(18):
                if not _recover_failed_to_load(driver):
                    time.sleep(1)
                    continue
                url_inp = _visible(driver, url_sel)
                if url_inp:
                    break
                _click_by_text(driver, _IDC_SWITCH_TEXTS)  # 恢复后切换按钮可能才出现
                time.sleep(1)
            reg_inp = _visible(driver, reg_sel)
            logger.info(f"[safari-apikey] 表单探测: url_inputs={len(url_inp)} "
                        f"region_inputs={len(reg_inp)}")
            if not url_inp:
                logger.warning("[safari-apikey] Start URL 框未渲染（failed-to-load 未恢复/结构变化），换新一轮")
                continue
            _react_fill(driver, url_inp[0], start_url)
            if reg_inp:
                _react_fill(driver, reg_inp[0], region)
            logger.info(f"[safari-apikey] 填 Start URL={start_url} Region={region}，Continue")
            _click_by_text(driver, ("Continue", "继续", "下一步", "Next", "Sign in", "登录"))
            time.sleep(3)
            logger.info(f"[safari-apikey] Continue 后 url={driver.current_url[:110]}")

            # ---- AWS IdC 登录（同 tab 跳转，过 WAF）----
            login_state = {"user": False, "temp": False, "new": False}
            aws_deadline = min(deadline, time.time() + 150)
            last_log = 0.0
            while time.time() < aws_deadline:
                if _kiro_logged_in(driver):
                    logger.info("[safari-apikey] 已回到 app.kiro.dev 登录态")
                    logged_in = True
                    break
                _capture_region(driver, region_box)
                if _waf_present(driver):
                    logger.warning("[safari-apikey] 出现 AWS WAF（真 Safari 罕见），等待…")
                    time.sleep(3)
                    continue
                # 回到 kiro.dev 时也可能崩成 failed-to-load，恢复它免得空转
                if "app.kiro.dev" in (driver.current_url or ""):
                    _recover_failed_to_load(driver)
                _aws_login_tick(driver, username, temp_pwd, new_pwd, login_state)
                now = time.time()
                if now - last_log >= 15:
                    last_log = now
                    try:
                        nt = len(_visible(driver, "input[type=text], input[type=email]"))
                        npw = len(_visible(driver, "input[type=password]"))
                        err = (driver.execute_script(
                            "return [...document.querySelectorAll('[role=alert],[class*=error i]')]"
                            ".map(e=>(e.innerText||'').trim()).filter(Boolean).slice(0,2).join(' | ')")
                            or "")
                        logger.info(f"[safari-apikey] 登录中 url={driver.current_url[:90]} "
                                    f"text_inputs={nt} pwd_inputs={npw} state={login_state} "
                                    f"err={err[:80]!r}")
                    except Exception:
                        pass
                time.sleep(2)
            if logged_in:
                break

        if not logged_in:
            try:
                driver.save_screenshot("scratch_safari_apikey_login_timeout.png")
            except Exception:
                pass
            raise RuntimeError("[safari-apikey] 多轮后仍未登录 api-keys 页"
                               "（截图 scratch_safari_apikey_login_timeout.png）")

        # ---- 建 key ----
        # 登录成功后 redirect_to_after_auth 通常已把页面带到 api-keys；若没（被弹主页），
        # 用重试深链确保真的落在 api-keys 页，否则建 key 入口按钮找不到（本 bug）。
        if not _on_apikeys_page(driver):
            logger.info(f"[safari-apikey] 登录后未在 api-keys 页(url={driver.current_url[:80]})，重试深链")
            if not _safari_goto_apikeys(driver):
                try:
                    driver.save_screenshot("scratch_safari_apikey_notonpage.png")
                except Exception:
                    pass
                raise RuntimeError("[safari-apikey] 登录后进不了 api-keys 页"
                                   "（深链被弹回主页；截图 scratch_safari_apikey_notonpage.png）")
        logger.info(f"[safari-apikey] 已确认在 api-keys 页，开始建 key url={driver.current_url[:80]}")
        _capture_region(driver, region_box)
        api_key = _safari_create_apikey(driver, key_name)
        if not api_key:
            try:
                driver.save_screenshot("scratch_safari_apikey_create_failed.png")
            except Exception:
                pass
            raise RuntimeError("[safari-apikey] 网页建 key 失败：未抓到完整 ksk_"
                               "（截图 scratch_safari_apikey_create_failed.png）")
        return {"apiKey": api_key, "region": region_box["region"]}
    finally:
        try:
            driver.quit()
        except Exception:
            pass
        if backend == "safari":
            _kill_stray_automation()  # safari 会话若失效 quit 关不掉窗口，兜底清掉
