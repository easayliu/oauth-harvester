"""AWS IAM Identity Center (IDC) 用户自动开通。

`aws-kiro` 模式调用：登录 AWS（Root 密码+TOTP 或 AK/SK 联邦）后，
  在 IAM Identity Center 自动建用户（选「Generate a one-time password」抓取一次性密码）。
产出一行 `idc::<start_url>----<username>----<one_time_pwd>----<new_pwd>`，可直接喂给
`python main.py kiro kiro_idc_users.txt` 完成 Kiro 设备流登录。

注意：AWS 控制台 UI 经常改版，本模块用多套兜底选择器 + 全程截图。首跑若某步没命中，
看 screenshots/<admin>/ 下的截图按实际 DOM 微调选择器即可。
"""

import asyncio
import datetime
import json
import logging
import os
import re
import secrets
import string
import time

from playwright.async_api import Page, BrowserContext

from app.accounts.aws import aws_console_login
from app.core.browser import screenshot_path

logger = logging.getLogger(__name__)


# ── 性能旋钮（批量建用户提速点，全部可用环境变量覆盖，默认值即「快」）──────────────
# 单个用户 ~86s 时，真正的耗时不是选择器命中，而是「诊断截图 + 固定 settle 睡眠 +
# 轮询间隔」三项纯等待。这里把它们收口到几个常量，既能整体提速、又可一键调回保守值。

# 截图模式：诊断截图是隐藏的大头（每个用户 ~8 张，繁忙 SPA 上每张 0.5~4s，累计 10s+）。
#   lean（默认）= 只在关键/失败节点留图（建表完成、提交后、抓到密码）——省掉最贵的 review 截图等；
#   full        = 全量截图（首次适配新版控制台 DOM、排错时用）；
#   off         = 完全不截图（最快）。
_SHOTS_MODE = os.getenv("AWS_IDC_SHOTS", "lean").strip().lower()

# 等待节奏系数：把所有 `_settle` 固定等待统一乘以该系数。控制台快时设 0.5 提速一倍，
# 遇到慢区域/限流再调回 1.0+。下限 200ms 防止过度压缩导致 SPA 还没重渲染就操作。
_SETTLE_SCALE = float(os.getenv("AWS_IDC_SETTLE_SCALE", "0.6"))

# 选择器轮询间隔：SPA 渲染有延迟需重试整组选择器；间隔越小命中越快（代价是探测更频繁）。
_POLL_MS = int(os.getenv("AWS_IDC_POLL_MS", "250"))


def _sso_users_url(region: str, instance_id: str) -> str:
    return (f"https://{region}.console.aws.amazon.com/singlesignon/home"
            f"?region={region}#/instances/{instance_id}/users")


def _sso_dashboard_url(region: str, instance_id: str) -> str:
    return (f"https://{region}.console.aws.amazon.com/singlesignon/home"
            f"?region={region}#/instances/{instance_id}/dashboard")


def _sso_home_url(region: str) -> str:
    return (f"https://{region}.console.aws.amazon.com/singlesignon/home"
            f"?region={region}#/instances")


_INSTANCE_ID_RE = re.compile(r"/instances/([A-Za-z0-9]+)")
_PORTAL_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+\.awsapps\.com/start")
_PORTAL_URL_APP_RE = re.compile(r"https://[A-Za-z0-9.-]+\.portal\.[a-z0-9-]+\.app\.aws[A-Za-z0-9/._-]*")
# AWS 一次性密码：含大小写+数字+符号的强口令，长度 >= 8。抓取时用宽松但带符号的形态，
# 优先匹配「含至少一个非字母数字符号」的 token，避免误抓普通单词。
_OTP_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9!@#$%^&*()_+=\[\]{};:,.?~-]{7,63}")


def gen_idc_user(prefix: str, domain: str, username: str = "") -> dict:
    """自动生成一个 IDC 用户身份：username / email / first / last / display。

    传入 username 时直接使用（如顺序命名 aws1/aws2…，由调用方分配序号）；不传则回退
    旧的随机 `<prefix>-<8位hex>` 命名。first/last 仅用于填表，不影响下游。"""
    if not username:
        token = secrets.token_hex(4)  # 8 位十六进制，足够避免撞名
        username = f"{prefix}-{token}"
    # 拆「字母前缀 + 尾部数字」做 first/last（仅填表用）；拆不出就整体当 first
    m = re.match(r"^(.*?)(\d+)$", username)
    first = (m.group(1) if m else username) or prefix or "Kiro"
    last = (m.group(2) if m else "") or "user"
    return {
        "username": username,
        "email": f"{username}@{domain}",
        "first_name": first.capitalize(),
        "last_name": last,
        "display_name": username,
    }


def gen_new_password() -> str:
    """为下游 Kiro 首登强制改密生成一个满足 IDC 复杂度的新密码（不含 '-'，避免与 ---- 分隔符冲突）。"""
    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    symbol = secrets.choice("!@#$%^&*")
    pool = string.ascii_letters + string.digits + "!@#$%^&*"
    rest = "".join(secrets.choice(pool) for _ in range(12))
    chars = list(upper + lower + digit + symbol + rest)
    # 洗牌（secrets 无 shuffle，用 SystemRandom）
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


async def _click_first(page: Page, selectors: list[str], desc: str,
                       timeout_ms: int = 8000, warn_on_miss: bool = True) -> bool:
    """轮询一组选择器，点击第一个可见可点的元素。命中返回 True。

    SPA 渲染有延迟，所以不是只查一次——每 _POLL_MS 重试整组选择器，直到命中或超时。
    元素一就绪就立刻点（快），还没渲染就耐心等（稳），避免「点早了」。
    timeout_ms=0 表示只查一次不轮询（用于「确实可能不存在」的可选元素）。

    超时按真实墙钟（monotonic deadline）算，而非只累加 wait_for_timeout(400) 的睡眠：
    后者在重页面上每轮探测（count/is_visible 往返）本身就要几秒，导致「10s」实际跑
    30s+，元素真的不存在时表现为长时间假死。"""
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        for sel in selectors:
            try:
                loc = page.locator(sel)
                n = await loc.count()
                for i in range(n):
                    cand = loc.nth(i)
                    try:
                        if await cand.is_visible() and await cand.is_enabled():
                            await cand.click()
                            logger.info(f"{desc}: 点击命中 (selector={sel}, idx={i})")
                            return True
                    except Exception:
                        continue
            except Exception:
                continue
        if time.monotonic() >= deadline:
            break
        await page.wait_for_timeout(_POLL_MS)
    if warn_on_miss:
        logger.warning(f"{desc}: 未命中任何选择器（超时 {timeout_ms}ms）")
    else:
        logger.debug(f"{desc}: 未命中任何选择器（超时 {timeout_ms}ms，非关键）")
    return False


# IDC「Specify user details」用户名输入框的兜底选择器（建用户向导专用）。
# 抽成常量供「首次填」与「提交前复查补填」复用，避免两处漂移。
_IDC_USERNAME_SELECTORS = [
    'input[id*="userName" i]', 'input[name*="userName" i]',
    'input[id*="username" i]', 'input[name*="username" i]',
    'input[placeholder*="user name" i]', 'input[placeholder*="username" i]',
    'input[placeholder*="Enter username" i]',
]


async def _idc_username_input(page: Page):
    """定位「Specify user details」里的用户名输入框，定位不到返回 None。
    label/xpath 先行，再退 CSS 兜底，与 _fill_field 的定位口径一致。"""
    for lab in ("用户名", "Username", "User name"):
        try:
            loc = page.get_by_label(lab, exact=False)
            if await loc.count() > 0 and await loc.first.is_visible():
                return loc.first
        except Exception:
            pass
    for xp in ('xpath=//*[normalize-space(text())="Username"]/following::input[1]',
               'xpath=//label[starts-with(normalize-space(.),"Username")]/following::input[1]'):
        try:
            loc = page.locator(xp)
            if await loc.count() > 0 and await loc.first.is_visible():
                return loc.first
        except Exception:
            pass
    for sel in _IDC_USERNAME_SELECTORS:
        try:
            loc = page.locator(sel)
            for i in range(await loc.count()):
                if await loc.nth(i).is_visible():
                    return loc.nth(i)
        except Exception:
            continue
    return None


async def _idc_ensure_username(page: Page, value: str) -> bool:
    """提交前复查：用户名框若为空（被「生成一次性密码」单选项触发的重渲染清掉，本 bug 根因），
    就地补填。已填对返回 True。"""
    loc = await _idc_username_input(page)
    if loc is None:
        logger.warning("IDC username 复查：未定位到用户名框，无法确认/补填")
        return False
    try:
        cur = await loc.input_value()
    except Exception:
        cur = None
    if cur == value:
        return True
    logger.warning(f"IDC username 复查：当前值={cur!r} 与目标不符，提交前补填")
    return await _robust_fill(loc, value, "IDC username 补填")


# JS：在「Password」分组里找到「Generate a one-time password」对应的 radio。
# do_click=true 时真实 .click() 它（提交到组件状态），否则只读 checked 状态。
# 返回 {found:bool, checked:bool}；found=false 表示页面上没找到该 radio。
_IDC_OTP_JS = """
(doClick) => {
  const hosts = Array.from(document.querySelectorAll('*')).filter(el => {
    const t = (el.textContent || '').toLowerCase();
    return /generate.*one.?time.*password/i.test(t)
        && el.children.length < 8 && el.offsetParent !== null;
  });
  if (!hosts.length) return {found: false, checked: false};
  const target = hosts[hosts.length - 1];   // 最贴近文本的宿主
  let p = target, radio = null;
  for (let i = 0; i < 8 && p; i++) {
    const r = p.querySelector('input[type="radio"], [role="radio"]');
    if (r) { radio = r; break; }
    p = p.parentElement;
  }
  if (!radio) return {found: false, checked: false};
  const isChecked = () => radio.tagName === 'INPUT'
      ? !!radio.checked : radio.getAttribute('aria-checked') === 'true';
  if (doClick && !isChecked()) radio.click();
  return {found: true, checked: isChecked()};
}
"""


async def _idc_otp_selected(page: Page):
    """读「一次性密码」单选项是否已选中。返回 True/False；定位不到该 radio 返回 None。"""
    try:
        res = await page.evaluate(_IDC_OTP_JS, False)
    except Exception as e:
        logger.debug(f"IDC OTP 状态读取异常: {e}")
        return None
    if not res or not res.get("found"):
        return None
    return bool(res.get("checked"))


async def _idc_ensure_otp(page: Page) -> bool:
    """提交前确认「生成一次性密码」单选项**确实选中**。

    之前只 _click_first 点一下文本 label 就算数（日志「点击命中」），但文本点击未必
    提交到 Cloudscape 组件状态，后续填邮箱/姓名触发的重渲染又把它打回默认的「发送邮件」
    （用户反馈：选完又回选回邮件）。这里真实 .click() radio 并回读 aria-checked/checked
    确认，未选中就重试。返回是否已选中（无法定位 radio 时返回 True 不阻塞，交给截图人工核对）。"""
    sel = await _idc_otp_selected(page)
    if sel is True:
        return True
    if sel is None:
        logger.warning("IDC OTP 复查：未定位到一次性密码 radio，跳过（请核对截图）")
        return True
    for _ in range(3):
        try:
            await page.evaluate(_IDC_OTP_JS, True)
        except Exception as e:
            logger.debug(f"IDC OTP 重选异常: {e}")
        await _settle(page, 250)
        if await _idc_otp_selected(page) is True:
            logger.info("IDC OTP 复查：已确认选中「生成一次性密码」")
            return True
    logger.warning("IDC OTP 复查：多次重选后仍未选中「生成一次性密码」")
    return False


async def _robust_fill(loc, value: str, desc: str) -> bool:
    """往一个已定位的输入框填值，并**回读确认值真的落进 DOM**了——只 fill 不校验是
    本流程「用户名填了却是空」的根因之一：Cloudscape 受控输入在某些渲染时序下 fill()
    不生效（或随后被组件重渲染清掉），而旧代码 fill 完即返回 True，从不复查。

    策略：先 fill；回读 input_value 不符就改用「聚焦→清空→逐字符键入」（press_sequentially
    触发真实 input 事件，最贴近用户手敲，受控组件必然收到 onChange）再复查。两次都不符返回 False。"""
    try:
        await loc.fill(value)
    except Exception as e:
        logger.debug(f"{desc}: fill 异常，转键入兜底: {e}")
    try:
        if (await loc.input_value()) == value:
            return True
    except Exception:
        pass
    # 兜底：逐字符键入。先点聚焦、整体清空，再 press_sequentially。
    try:
        await loc.click(timeout=2000)
        await loc.fill("")
        await loc.press_sequentially(value, delay=15)
        if (await loc.input_value()) == value:
            logger.info(f"{desc}: fill 未生效，已用逐字符键入兜底填入")
            return True
    except Exception as e:
        logger.debug(f"{desc}: 键入兜底失败: {e}")
    return False


async def _fill_first(page: Page, selectors: list[str], value: str, desc: str,
                      timeout_ms: int = 8000) -> bool:
    """轮询一组选择器，往第一个可见 input 填值。命中返回 True。
    timeout_ms=0 表示只查一次不轮询。超时按真实墙钟算（理由见 _click_first）。"""
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        for sel in selectors:
            try:
                loc = page.locator(sel)
                n = await loc.count()
                for i in range(n):
                    cand = loc.nth(i)
                    try:
                        if await cand.is_visible() and await _robust_fill(cand, value, desc):
                            logger.info(f"{desc}: 已填入 (selector={sel}, idx={i})")
                            return True
                    except Exception:
                        continue
            except Exception:
                continue
        if time.monotonic() >= deadline:
            break
        await page.wait_for_timeout(_POLL_MS)
    if timeout_ms > 0:  # 单查模式（timeout_ms=0，供 _fill_field 兜底）不刷告警
        logger.warning(f"{desc}: 未找到可填的输入框（超时 {timeout_ms}ms）")
    return False


async def _settle(page: Page, ms: int = 900) -> None:
    """AWS 控制台是 SPA，后台长轮询/websocket 让 networkidle 几乎永不触发，
    `wait_for_load_state("networkidle")` 每次都白等满 timeout（15s×N=整条流程的主要耗时）。
    这里用一个短的固定等待代替，够 SPA 重渲染即可。

    传入的 ms 是「保守基准值」，实际等待 = ms × _SETTLE_SCALE（默认 0.6，整体提速），
    并设 200ms 下限避免压得太狠让 SPA 还没重渲染就操作。改 AWS_IDC_SETTLE_SCALE 一键调节。"""
    eff = max(200, int(ms * _SETTLE_SCALE)) if ms > 0 else 0
    try:
        await page.wait_for_timeout(eff)
    except Exception:
        pass


async def _shot(page: Page, name: str, admin: str = None, key: bool = False) -> None:
    """诊断用截图，必须「尽力而为、绝不阻塞主流程」。

    page.screenshot() 默认会等页面视觉稳定（最长 30s）才落盘：IDC review 步等页面
    仍在动画/加载时，单张截图能卡满 ~30s，甚至超时抛错中断整条建用户流程（曾观测到
    群组页→提交之间 33s 空档，根因就是这张 review 截图）。这里禁用动画（立即定格）、
    超时压到 4s、并吞掉所有异常——截图只是排错素材，不该挡路。

    分级（按 _SHOTS_MODE）：诊断截图是批量建用户的隐藏大头（每用户 ~8 张）。
      off  = 一张不截；
      lean = 只截 key=True 的关键节点（建表完成 / 提交后 / 抓到密码）——默认，省掉最贵的 review 截图；
      full = 全量截图（排错/适配新版 DOM）。"""
    if _SHOTS_MODE == "off":
        return
    if _SHOTS_MODE != "full" and not key:  # lean：只留关键截图
        return
    try:
        await page.screenshot(path=screenshot_path(name, admin),
                              animations="disabled", timeout=4000)
    except Exception as e:
        logger.debug(f"截图 {name} 跳过（不影响流程）: {e}")


# 复制下来的整段登录信息里，一次性密码总带明确标签（中/英）。按标签取值最准，
# 避免误把同样「字母+数字、长度≥12」的用户名（如 culusow71022）当成密码。
_OTP_LABEL_RE = re.compile(
    r"(?:一次性密码|一次性密碼|临时密码|臨時密碼|"
    r"[Oo]ne[-\s]?time\s+password|[Tt]emporary\s+password)\s*[:：]\s*(\S+)")


def _extract_otp_by_label(blob: str) -> str:
    """优先按「一次性密码: xxx」/「One-time password: xxx」标签提取密码值。

    标签已把值精确锚定到密码本身，故 @ ! % 等特殊字符照收——AWS 一次性密码常含 @，
    之前用 "@" not in cand 把含 @ 的密码全滤掉了（这一批 10 个里 4 个就栽在这）。
    只挡明显是 URL 的值（密码不会是 http(s):// 或 awsapps 链接）。"""
    m = _OTP_LABEL_RE.search(blob or "")
    if m:
        cand = m.group(1).strip()
        if cand and not cand.startswith(("http://", "https://")) and "awsapps" not in cand:
            return cand
    return ""


# AWS 一次性密码恒为 ASCII 可见字符（无空白、无中文、无引号）。用它挡掉「成功提示」之类
# 含中文/引号的 token 被误当成密码（如 `已成功添加用户"xxx"。`，见反馈截图）。
_ASCII_TOKEN_RE = re.compile(r"^[\x21-\x7e]+$")


def _looks_like_otp(text: str, exclude: str = "") -> str:
    """从一段文本里判定/提取一次性密码：单段、足够长、ASCII 可见字符、不是 URL/邮箱/已知前缀。
    exclude：要排除的 token（通常是用户名——它也可能恰好长得像密码，须跳过）。"""
    text = (text or "").strip()
    if not text:
        return ""
    bad_prefix = ("d-", "ssoins-", "kiro-")
    if (8 <= len(text) <= 128 and _ASCII_TOKEN_RE.match(text)
            and "http" not in text and "@" not in text and "awsapps" not in text
            and "app.aws" not in text and not text.startswith(bad_prefix)
            and text != exclude):
        return text
    for tok in re.split(r"\s+", text):
        if tok == exclude:
            continue
        if (12 <= len(tok) <= 128 and _ASCII_TOKEN_RE.match(tok)
                and "http" not in tok and "@" not in tok and "awsapps" not in tok
                and "app.aws" not in tok and not tok.startswith(bad_prefix)
                and any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok)):
            return tok
    return ""


async def _fill_field(page: Page, labels: list[str], value: str,
                      fallback_selectors: list[str], desc: str,
                      timeout_ms: int = 8000) -> bool:
    """按多种策略定位并填一个表单字段，轮询直到命中或超时：
      1) get_by_label（标签经 <label for>/aria-labelledby 关联到输入框时有效）
      2) XPath：标签文本节点之后紧邻的第一个 input/textarea
         （IDC 控制台 FormField 结构常是「标签文本 → 输入框」堆叠，关联属性不一定齐）
      3) CSS 兜底选择器
    SPA 渲染有延迟，所以整组策略每 _POLL_MS 重试一次，直到命中或超时（墙钟，理由见 _click_first）。"""
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        for lab in labels:
            try:
                loc = page.get_by_label(lab, exact=False)
                if await loc.count() > 0:
                    first = loc.first
                    if await first.is_visible() and await _robust_fill(first, value, desc):
                        logger.info(f"{desc}: 按 label「{lab}」填入")
                        return True
            except Exception:
                continue

        for lab in labels:
            for xp in (
                f'xpath=//*[normalize-space(text())="{lab}"]/following::input[1]',
                f'xpath=//label[starts-with(normalize-space(.),"{lab}")]/following::input[1]',
                f'xpath=//*[normalize-space(text())="{lab}"]/following::textarea[1]',
            ):
                try:
                    loc = page.locator(xp)
                    if await loc.count() > 0:
                        first = loc.first
                        if await first.is_visible() and await _robust_fill(first, value, desc):
                            logger.info(f"{desc}: 按 xpath 标签「{lab}」后第一个输入框填入")
                            return True
                except Exception:
                    continue

        # 兜底选择器只单查一次（timeout_ms=0），避免与外层轮询叠加
        if fallback_selectors and await _fill_first(page, fallback_selectors, value, desc, timeout_ms=0):
            return True

        if time.monotonic() >= deadline:
            break
        await page.wait_for_timeout(_POLL_MS)
    logger.warning(f"{desc}: 未定位到字段（超时 {timeout_ms}ms）labels={labels}")
    return False


async def _idc_fill_email_pair(page: Page, email: str) -> None:
    """填「电子邮箱」+「确认邮件地址」。两个框 placeholder 都是 email@example.com，
    先按 label 定位，任一未命中再按 DOM 出现顺序兜底（第 1 个=邮箱，第 2 个=确认）。"""
    ok_main = await _fill_field(
        page, ["电子邮箱", "电子邮件地址", "Email address", "Email"], email,
        [], "IDC email 主")
    ok_confirm = await _fill_field(
        page, ["确认邮件地址", "确认电子邮件地址", "确认电子邮件", "Confirm email", "Confirm"], email,
        [], "IDC email 确认")
    if ok_main and ok_confirm:
        return

    cand = page.locator(
        'input[type="email"], input[placeholder="email@example.com"], '
        'input[placeholder*="example.com" i]')
    visible = []
    try:
        n = await cand.count()
    except Exception:
        n = 0
    for i in range(n):
        el = cand.nth(i)
        try:
            if await el.is_visible():
                visible.append(el)
        except Exception:
            continue
    if not ok_main and len(visible) >= 1:
        await visible[0].fill(email)
        logger.info("IDC email 主: 位置兜底填入")
    if not ok_confirm and len(visible) >= 2:
        await visible[1].fill(email)
        logger.info("IDC email 确认: 位置兜底填入")
    elif not ok_confirm:
        logger.warning("IDC email 确认: 仍未找到确认邮箱框，提交可能报「不匹配」")


async def _idc_resolve_instance_id(page: Page, region: str, default_id: str) -> str:
    """进入 SSO 控制台，确定当前账号的 Identity Center 实例 ID。
    优先用 default_id；没配则打开 SSO home 让 AWS 重定向，从 URL 抓 /instances/<id>。"""
    if default_id:
        return default_id
    logger.info("未配置 AWS_IDC_INSTANCE_ID，打开 SSO 控制台自动探测实例 ID...")
    await page.goto(_sso_home_url(region), wait_until="domcontentloaded")
    await _settle(page, 700)
    for _ in range(20):  # ~10s 等 hash 重定向到具体实例
        m = _INSTANCE_ID_RE.search(page.url)
        if m:
            inst = m.group(1)
            logger.info(f"探测到 Identity Center 实例 ID: {inst}")
            return inst
        await page.wait_for_timeout(500)
    raise RuntimeError("无法探测 Identity Center 实例 ID，请在 config.py 配置 AWS_IDC_INSTANCE_ID")


async def _idc_read_portal_url(page: Page, region: str, instance_id: str, admin: str) -> str:
    """从 IDC dashboard 抓 AWS access portal URL（d-xxx.awsapps.com/start 或 *.portal.<region>.app.aws）。"""
    await page.goto(_sso_dashboard_url(region, instance_id), wait_until="domcontentloaded")
    await _settle(page, 700)
    await _settle(page)
    await _shot(page, "idc_dashboard", admin)
    for _ in range(20):
        try:
            body = await page.locator("body").inner_text()
        except Exception:
            body = ""
        m = _PORTAL_URL_RE.search(body) or _PORTAL_URL_APP_RE.search(body)
        if m:
            url = m.group(0)
            logger.info(f"IDC access portal URL: {url}")
            return url
        await page.wait_for_timeout(500)
    logger.warning("未在 dashboard 抓到 access portal URL")
    return ""


async def _idc_create_user(page: Page, region: str, instance_id: str,
                           user: dict, admin: str, group_name: str = "") -> str:
    """在 IAM Identity Center「Add user」向导里建用户，选「Generate a one-time password」，
    （可选）在「添加到群组」那一步勾选 group_name，最后提交。
    返回从结果弹窗「复制」抓到的**整段登录信息**（portal URL + 用户名 + 一次性密码；抓不到返回空串）。"""
    await page.goto(_sso_users_url(region, instance_id), wait_until="domcontentloaded")
    await _settle(page, 700)
    await _settle(page)
    await _shot(page, "idc_users_landing", admin)

    # 1) 进入「Add user」向导（控制台首屏渲染慢，给足轮询时间）
    await _click_first(page, [
        'button:has-text("Add user")', 'a:has-text("Add user")',
        'button:has-text("添加用户")', 'a:has-text("添加用户")',
        'button:has-text("Add users")', 'a:has-text("Add users")',
    ], "IDC Add user", timeout_ms=20000)
    await _shot(page, "idc_add_user_step1", admin)

    # 2) Step1：用户详情（向导表单渲染也要等，username 字段给足轮询时间）
    await _fill_field(page, ["用户名", "Username", "User name"], user["username"],
                      _IDC_USERNAME_SELECTORS, "IDC username", timeout_ms=15000)
    await _settle(page, 500)

    # 选「生成一次性密码」单选项（默认是「发送邮件」，必须显式切换）
    # AWS Console 现在用 Cloudscape Design System，单选钮真实 DOM 可能是：
    #   旧:  <label><input type=radio>Generate a one-time password</label>
    #   新:  <div role=radio aria-checked=false>...</div>
    #   或:  <span class=awsui_radio-button-wrapper>...<input type=radio>...
    # 选择器从单一 label 扩到覆盖 Cloudscape + role + data-testid。超时 8s → 15s
    # 防 hydration 慢擦边。
    clicked_otp = await _click_first(page, [
        # 文本路径 —— Playwright text= 匹配任意可见文本节点，最直接
        'text=Generate a one-time password',
        'text=/[Gg]enerate.*one.time.password/',
        # 中文
        'text=生成一个可以与此用户共享的一次性密码',
        'label:has-text("一次性密码")',
        # Cloudscape role-based
        '[role="radio"]:has-text("one-time password")',
        '[role="radio"]:has-text("One-time password")',
        # 容器路径
        'label:has(input[type="radio"]):has-text("one-time password")',
        'div:has(input[type="radio"]):has-text("one-time password")',
        'span:has(input[type="radio"]):has-text("one-time password")',
        # data-testid（AWS Console 部分组件有 testid）
        '[data-testid*="one-time" i]',
        '[data-testid*="onetime" i]',
        # input value
        'input[type="radio"][value*="ONE_TIME" i]',
        'input[type="radio"][value*="oneTime" i]',
        # 旧 label 路径
        'label:has-text("Generate a one-time password")',
        'label:has-text("one-time password")',
    ], "IDC 选一次性密码选项", timeout_ms=15000)

    if not clicked_otp:
        # 兜底 1：JS 文本邻近 —— 完全不依赖 CSS 选择器形状，找含 "one-time password"
        # 文字的最近祖先里的 radio（包含 <input type=radio> 或 [role=radio]）。
        # 比位置/计数兜底更鲁棒：AWS Console 即使在 Password section 加了别的 radio
        # 也能精准点对的那一个。
        try:
            clicked_via_js = await page.evaluate(
                """
                () => {
                  // 找包含目标文本的最小文本宿主（避免抓到 body）
                  const all = Array.from(document.querySelectorAll('*'));
                  const candidates = all.filter(el => {
                    const t = (el.textContent || '').toLowerCase();
                    return /generate.*one.?time.*password/i.test(t)
                        && el.children.length < 8
                        && el.offsetParent !== null;
                  });
                  if (!candidates.length) return false;
                  // 取最深的（最贴近文本的）
                  const target = candidates[candidates.length - 1];
                  // 向上爬最多 8 层，找最近的 radio
                  let p = target;
                  for (let i = 0; i < 8 && p; i++) {
                    const r = p.querySelector('input[type="radio"], [role="radio"]');
                    if (r) { r.click(); return true; }
                    p = p.parentElement;
                  }
                  return false;
                }
                """
            )
            if clicked_via_js:
                clicked_otp = True
                logger.info("IDC 选一次性密码选项: JS 文本邻近兜底命中")
        except Exception as e:
            logger.debug(f"JS 文本邻近兜底失败: {e}")

    if not clicked_otp:
        # 兜底 2：位置 —— 密码选项组通常只有 2 个 radio，第 2 个是一次性密码。
        # 放宽限制：>=2 个也支持，取倒数第一个（最后渲染的通常是非默认项）。
        try:
            radios = page.locator('input[type="radio"], [role="radio"]')
            n = await radios.count()
            if n >= 2:
                idx = 1 if n == 2 else n - 1
                last = radios.nth(idx)
                try:
                    await last.check(timeout=2000)
                except Exception:
                    await last.click(timeout=2000)
                clicked_otp = True
                logger.info(f"IDC 选一次性密码选项: 位置兜底选中第 {idx} 个 radio（共 {n} 个）")
        except Exception as e:
            logger.debug(f"位置兜底失败: {e}")

    if not clicked_otp:
        logger.warning("未能选中「生成一次性密码」，将抓不到一次性密码，请核对截图")

    # 邮箱 + 确认邮箱（两框 placeholder 相同，单独处理）
    await _idc_fill_email_pair(page, user["email"])

    # 名字 / 姓氏
    await _fill_field(page, ["名字", "First name"], user["first_name"], [
        'input[id*="firstName" i]', 'input[name*="firstName" i]',
        'input[placeholder*="first name" i]',
    ], "IDC first name")
    await _fill_field(page, ["姓氏", "Last name"], user["last_name"], [
        'input[id*="lastName" i]', 'input[name*="lastName" i]',
        'input[placeholder*="last name" i]',
    ], "IDC last name")
    # 显示名称默认会被自动填成「名字 姓氏」，导致下游 Amazon Q 按「显示名称」搜不到该用户。
    # 显式覆盖成 username，与 gen_idc_user 的 display_name 一致。
    await _fill_field(page, ["显示名称", "Display name"], user["display_name"], [
        'input[id*="displayName" i]', 'input[name*="displayName" i]',
    ], "IDC display name")
    await _settle(page, 500)

    # 提交前把两件互相牵连的事一起钉死，再点「下一步」：
    #   ① 用户名已填——它是唯一在「选一次性密码」之前就填的字段，单选项重渲染会把它清空
    #      （bug 一：截图里只有用户名空、其余都在）；
    #   ② 一次性密码单选项确实选中——文本点击未提交到组件状态，填邮箱/姓名的重渲染又把它
    #      打回默认「发送邮件」（bug 二：选完又回选回邮件）。
    # 两者的补填/重选会各自触发重渲染、可能再清掉对方，故用收敛循环：每轮都补一遍，
    # 直到一轮结束时两者**同时**成立（先 username 后 OTP，让 OTP 成为最后动作，紧贴下一步）。
    for _ in range(3):
        u_ok = await _idc_ensure_username(page, user["username"])
        o_ok = await _idc_ensure_otp(page)
        # 复查 username 是否仍在（OTP 重选可能又把它清掉）
        cur_u = await _idc_username_input(page)
        u_still = False
        if cur_u is not None:
            try:
                u_still = (await cur_u.input_value()) == user["username"]
            except Exception:
                u_still = False
        if u_ok and u_still and o_ok:
            break
        await _settle(page, 300)
    else:
        logger.warning("IDC 提交前未能同时钉住 用户名+一次性密码，提交可能失败，请核对截图")
    await _shot(page, "idc_add_user_filled", admin, key=True)

    # 提交向导：详情页「下一步」→「添加到群组」页（勾选 group）→「下一步」→ review →「添加用户」。
    # 每步都**确认主标题真的切过去**了再继续，不再「点了 Next 就当推进了」（本次根因：
    # 群组页 Next 点了没生效，向导一直卡在群组页，后续提交点到的其实是群组页的橙色 Next）。
    # 详情页 → 群组页
    if not await _idc_advance_step(page, "groups", admin):
        logger.warning("IDC 未能从详情页进入群组页（看 idc_groups_step 截图）")
    await _settle(page, 600)
    await _shot(page, "idc_groups_step", admin)

    # 「添加到群组」页：默认不加组，直接下一步；只有显式传了 group_name 才勾选
    if group_name:
        await _idc_select_group(page, group_name, admin)

    # 群组页 → review 页
    if not await _idc_advance_step(page, "review", admin):
        logger.warning("IDC 未能从群组页进入 review 页，提交可能失败（看 idc_review_step 截图）")
    await _settle(page, 600)
    await _shot(page, "idc_review_step", admin)

    # review → 添加用户（提交）。提交按钮文案与向导入口按钮完全相同，SPA 里残留的
    # 用户列表页「添加用户」按钮可能仍可见可点，_click_first 的 idx=0 会先点到它 →
    # 日志显示「点击命中」却根本没提交、结果弹窗永不出现（本次根因）。故改为：
    # ① 先用 review footer 的 primary 变体精确定位提交按钮；② 点完轮询确认确实生效，
    # 没生效就重试。
    submitted = await _idc_submit_review(page, admin)
    if not submitted:
        logger.warning("IDC 向导未点到最终「添加用户」(或提交未生效)，用户可能未创建")
    await _settle(page, 800)
    await _shot(page, "idc_after_submit", admin, key=True)

    await _shot(page, "idc_one_time_password", admin)
    return await _idc_capture_login_info(page, admin)


async def _idc_click_next(page: Page, desc: str, timeout_ms: int = 8000) -> bool:
    """点向导「下一步 / Next」按钮，返回是否点到。

    用 :has-text 子串选择器先取到候选（它确实能匹配到真正的 Next 按钮），再在 Python 里
    按 innerText **以「next/下一步」开头**过滤——这一步是关键：
      根因：:has-text("Next") 是「子串、忽略大小写」匹配，会把账号名含「next」的右上角账号
      切换按钮也命中（如账号「aldexnext」小写含 "next"），且账号按钮在 DOM 里排在向导底部
      按钮之前（idx=0），于是每次都点到它、弹出账号菜单，真正的 Next 永远点不到。
      而账号按钮文本是「aldexnext…」**不以 next 开头**，故按前缀过滤即可精确排除它；
    又因为之前试过 :text-is("Next") 精确匹配会一个都匹配不到（Cloudscape 按钮文本并非正好
    是「Next」，可能带 sr-only/空白），所以这里用「子串命中 + 前缀过滤」而非精确匹配。"""
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        for sel in ('button:has-text("下一步")', 'button:has-text("Next")'):
            try:
                loc = page.locator(sel)
                n = await loc.count()
            except Exception:
                continue
            for i in range(n):
                cand = loc.nth(i)
                try:
                    if not (await cand.is_visible() and await cand.is_enabled()):
                        continue
                    txt = ((await cand.inner_text()) or "").strip().lower()
                    # 只认文本以 next/下一步 开头的；账号按钮文本「aldexnext…」不以 next 开头，排除
                    if not (txt.startswith("next") or txt.startswith("下一步")):
                        continue
                    await cand.click()
                    logger.info(f"{desc}: 点击命中 (selector={sel}, idx={i}, text={txt[:20]!r})")
                    return True
                except Exception:
                    continue
        if time.monotonic() >= deadline:
            break
        await page.wait_for_timeout(_POLL_MS)
    logger.warning(f"{desc}: 未命中「下一步/Next」按钮（超时 {timeout_ms}ms）")
    return False


# 建用户向导三步的页面主标题（中/英）。用它确认每次「下一步」**真的把向导推进到了目标步**，
# 而不是「日志写了点击命中、SPA 却还停在原步」——本次根因：群组页 Next 点了没生效，随后
# variant-primary 又点回群组页那颗橙色 Next，向导从未进入 review，结果弹窗永不出现 → 45s 抓不到密码。
_IDC_STEP_HEADINGS = {
    "details": ["指定用户详细信息", "Specify user details"],
    "groups":  ["将用户添加到组", "添加用户到组", "Add user to groups"],
    "review":  ["查看并添加用户", "Review and add user"],
}


async def _idc_heading_has(page: Page, texts: list[str]) -> bool:
    """页面主标题（h1/h2/role=heading）是否含给定文案之一（只认可见的标题元素，
    避免命中正文里的回显文本，如 review 页正文也会出现「步骤 1：指定用户详细信息」）。"""
    for t in texts:
        try:
            loc = page.locator(
                f'h1:has-text("{t}"), h2:has-text("{t}"), [role="heading"]:has-text("{t}")')
            for i in range(await loc.count()):
                if await loc.nth(i).is_visible():
                    return True
        except Exception:
            continue
    return False


async def _idc_current_step(page: Page) -> str:
    """识别建用户向导当前所处步骤：review/groups/details/unknown。
    review 最先判：它的页面正文里也会回显「步骤 1：指定用户详细信息」，必须先认 review 再认 details。"""
    for step in ("review", "groups", "details"):
        if await _idc_heading_has(page, _IDC_STEP_HEADINGS[step]):
            return step
    return "unknown"


async def _idc_advance_step(page: Page, target: str, admin: str,
                            max_attempts: int = 4) -> bool:
    """点「下一步」把向导推进到 target 步，并**回读主标题确认确实切到了 target** 才算数。
    SPA 转场时同名「Next」可能点了不生效、或点到转场中残留的旧按钮，故每轮都重点一次并
    轮询确认，最多 max_attempts 次。Next 按钮用 _idc_click_next 点击（按前缀过滤，避免点到
    账号名含「next」的右上角账号按钮，本次根因）。"""
    for attempt in range(1, max_attempts + 1):
        if await _idc_current_step(page) == target:
            return True
        await _idc_click_next(page, f"IDC 进入「{target}」步 第{attempt}次下一步", timeout_ms=8000)
        # 轮询确认主标题切到目标步（建用户是服务端往返，转场可能要 1~3s）
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline:
            await page.wait_for_timeout(400)
            if await _idc_current_step(page) == target:
                logger.info(f"IDC 向导已进入「{target}」步（第{attempt}次下一步）")
                return True
        logger.warning(f"IDC 点了下一步但未进入「{target}」步，重试（第{attempt}次）")
        await _settle(page, 600)
    logger.warning(f"IDC 多次下一步仍未进入「{target}」步，向导可能卡住")
    return False


# review footer 的提交按钮：Cloudscape 主操作按钮带 variant-primary 类，用它把提交按钮
# 和「入口/列表页同名按钮」区分开（两者文案都是「添加用户」/「Add user」）。
_IDC_SUBMIT_PRIMARY = (
    'button[class*="variant-primary" i]:has-text("添加用户"), '
    'button[class*="variant-primary" i]:has-text("Add user")')


async def _idc_submit_took_effect(page: Page, timeout_ms: int = 8000) -> bool:
    """提交后轮询确认是否真生效：结果弹窗（含一次性密码/复制）出现，
    或 review 的 primary 提交按钮不再可见可点（已进入提交态/已离开 review 页）。
    点到的是残留入口按钮时，review 提交按钮仍在 → 返回 False，触发重试。"""
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        try:
            dlg = page.locator('div[role="dialog"]')
            if await dlg.count() > 0 and await dlg.first.is_visible():
                txt = ((await dlg.first.inner_text()) or "")
                low = txt.lower()
                if ("一次性密码" in txt or "one-time password" in low
                        or "复制" in txt or "copy" in low):
                    return True
        except Exception:
            pass
        try:
            btn = page.locator(_IDC_SUBMIT_PRIMARY)
            still = False
            for i in range(await btn.count()):
                b = btn.nth(i)
                if await b.is_visible() and await b.is_enabled():
                    still = True
                    break
            if not still:
                return True
        except Exception:
            pass
        if time.monotonic() >= deadline:
            return False
        await page.wait_for_timeout(500)


async def _idc_submit_review(page: Page, admin: str, max_attempts: int = 3) -> bool:
    """点 review 步「添加用户」提交并确认生效，没生效就重试（最多 max_attempts 次）。
    选择器把 primary 变体放最前，优先点到 review footer 的真正提交按钮，避免误点
    SPA 里残留的入口/列表页同名按钮。"""
    submit_selectors = [
        _IDC_SUBMIT_PRIMARY,
        'button:has-text("完成")', 'button:has-text("Finish")',
        'button:has-text("提交")', 'button:has-text("Submit")',
        'button:has-text("添加用户")', 'button:has-text("Add user")',
        'button[class*="variant-primary" i]',
    ]
    for attempt in range(1, max_attempts + 1):
        # 只在 review 步点提交。① 第一次就不在 review = 向导没推到位（上游已告警），硬点
        # variant-primary 只会点到列表页残留的「添加用户」入口、把向导重开（本次 bug 的连锁）；
        # ② 重试时若已离开 review，说明上一次提交其实生效了（只是弹窗慢没被 _took_effect 抓到），
        # 直接当成功返回，绝不再点（再点必然误触发入口按钮）。
        step = await _idc_current_step(page)
        if step != "review":
            if attempt == 1:
                logger.warning(f"IDC 提交前不在 review 步（当前={step}），跳过点击避免误点入口按钮")
                return False
            logger.info(f"IDC 已离开 review 步（当前={step}），视为已提交，不再重点")
            return True
        clicked = await _click_first(
            page, submit_selectors, f"IDC 提交(添加用户) 第{attempt}次", timeout_ms=20000)
        if not clicked:
            return False
        if await _idc_submit_took_effect(page):
            logger.info(f"IDC 提交已生效（第{attempt}次点击）")
            return True
        logger.warning(f"IDC 提交点击后未见生效（疑似点到残留按钮/校验未过），重试（第{attempt}次）")
        await _settle(page, 1200)
    logger.warning("IDC 多次点击「添加用户」仍未见提交生效，用户可能未创建")
    return False


async def _idc_select_group(page: Page, group_name: str, admin: str) -> bool:
    """在向导「添加到群组」页，搜索并勾选指定群组。原生 checkbox 常视觉隐藏，
    点该行内可见的复选框容器/label 即可。"""
    # 有搜索框就先搜一下（缩短列表）
    await _fill_first(page, [
        f'input[placeholder*="群组" i]', f'input[placeholder*="group" i]',
        f'input[placeholder*="搜索" i]', f'input[placeholder*="Search" i]',
        'input[type="search"]',
    ], group_name, "IDC 搜索群组", timeout_ms=4000)
    await _settle(page, 900)
    ok = await _click_first(page, [
        f'xpath=//tr[contains(normalize-space(.),"{group_name}")]//input[@type="checkbox"]/..',
        f'xpath=//tr[contains(normalize-space(.),"{group_name}")]//label',
        f'xpath=//*[@role="row"][contains(normalize-space(.),"{group_name}")]//input[@type="checkbox"]/..',
        f'xpath=//*[@role="row"][contains(normalize-space(.),"{group_name}")]//label',
        f'tr:has-text("{group_name}") input[type="checkbox"]',
        f'label:has-text("{group_name}")',
    ], f"IDC 勾选群组 {group_name}", timeout_ms=10000)
    if not ok:
        logger.warning(f"未能勾选群组「{group_name}」（看 idc_groups_step 截图，确认群组名/列表）")
    await _shot(page, "idc_group_selected", admin)
    return ok


async def _idc_advance_wizard(page: Page, admin: str, max_steps: int = 6) -> bool:
    """提交「添加用户」向导，返回是否点到了最终提交按钮。

    不再用文本探测结果页——表单里一次性密码单选项的文案就含「一次性密码」，会误判成
    已完成而根本不点提交（之前用户没被创建的根因）。改用确定的向导规则：
      本步有「下一步」就点它进入下一步；没有「下一步」即到了 review 步，点「添加用户/完成」提交。
    """
    for step in range(1, max_steps + 1):
        nxt = await _idc_click_next(page, f"IDC 向导下一步(第{step}步)", timeout_ms=4000)
        if nxt:
            await _settle(page, 700)
            await _settle(page)
            await _shot(page, f"idc_wizard_step_{step}", admin)
            continue

        # 没有「下一步」→ review 步，点最终提交
        submitted = await _click_first(page, [
            'button:has-text("添加用户")', 'button:has-text("Add user")',
            'button:has-text("完成")', 'button:has-text("Finish")',
            'button:has-text("提交")', 'button:has-text("Submit")',
            'button[class*="variant-primary" i]',
            '[role="button"][class*="variant-primary" i]',
            'input[type="submit"]',
        ], "IDC 向导提交(添加用户)")
        await _settle(page, 700)
        await _settle(page)
        await _shot(page, "idc_after_submit", admin)
        return submitted

    logger.warning("IDC 向导达到最大步数仍未提交（疑似字段校验未过）")
    return False


def _looks_like_login_info(text: str) -> bool:
    """判断剪贴板内容是不是「登录信息整段」（含 portal URL / 一次性密码字样 / 像密码的 token）。"""
    if not text:
        return False
    low = text.lower()
    if "awsapps" in low or ".app.aws" in low:
        return True
    if "一次性密码" in text or "one-time password" in low or "password" in low:
        return True
    return bool(_looks_like_otp(text))


def _parse_idc_login_info(blob: str, username: str = "") -> dict:
    """从复制下来的整段登录信息里解析出 start_url（优先 awsapps/start）+ 一次性密码。
    一次性密码优先按标签精确取值，取不到再用启发式（并排除 username，避免误抓用户名）。"""
    start_url = ""
    m = _PORTAL_URL_RE.search(blob or "")
    if m:
        start_url = m.group(0)
    else:
        m = _PORTAL_URL_APP_RE.search(blob or "")
        if m:
            start_url = m.group(0)
    otp = _extract_otp_by_label(blob) or _looks_like_otp(blob, exclude=username)
    return {"start_url": start_url, "one_time_password": otp}


def _page_origin(page: Page) -> str:
    """取当前页面的 origin（scheme://host），用于按真实区域授予剪贴板权限。
    区域可能不是 us-east-1（如 --region 覆盖），拿不到就回退 us-east-1。"""
    m = re.match(r"(https?://[^/]+)", page.url or "")
    return m.group(1) if m else "https://us-east-1.console.aws.amazon.com"


async def _idc_read_dialog_text(page: Page) -> str:
    """直接读「添加用户」结果弹窗的整段可见文本（含 portal URL + 用户名 + 一次性密码）。
    作为剪贴板路径失效（无焦点/无权限/读空）时的兜底——DOM 文本不依赖剪贴板，最稳。"""
    for sel in ['div[role="dialog"]', '[role="alertdialog"]', '[class*="modal" i]']:
        try:
            loc = page.locator(sel).first
            if await loc.count() > 0 and await loc.is_visible():
                txt = (await loc.inner_text() or "").strip()
                if _looks_like_login_info(txt):
                    return txt
        except Exception:
            continue
    return ""


async def _idc_copy_read_raw(page: Page, selector: str) -> str:
    """点击 selector 命中的复制按钮（逐个尝试可见的），点完读剪贴板，
    返回**整段原文**（只要内容像登录信息就返回，不再只抽密码）。"""
    try:
        loc = page.locator(selector)
        n = await loc.count()
    except Exception:
        return ""
    for i in range(n):
        cand = loc.nth(i)
        try:
            if not await cand.is_visible():
                continue
            await cand.click()
            await page.wait_for_timeout(350)
            clip = (await page.evaluate("() => navigator.clipboard.readText()") or "").strip()
            if _looks_like_login_info(clip):
                return clip
            if clip:
                logger.debug(f"复制后剪贴板内容不像登录信息（len={len(clip)}）")
        except Exception:
            continue
    return ""


async def _idc_capture_login_info(page: Page, admin: str) -> str:
    """点弹窗里的大「复制 / Copy」按钮，返回剪贴板里**整段登录信息**
    （默认/双栈 portal URL + 用户名 + 一次性密码）。把全部抓下来保存，不只抽密码。

    不去点密码行的图标/anchored 按钮：那容易误点到「关闭/X」把弹窗关掉（之前失败的原因）。

    取数有两条路径，剪贴板优先（格式最完整、带标签），失败自动兜底读弹窗 DOM 文本：
    剪贴板依赖焦点+权限，偶尔读空；DOM 文本不依赖剪贴板，最稳，不再「点了复制却抓不到」。
    """
    # 剪贴板读取需要标签页持有焦点，否则 readText() 静默读空——先把页面提到前台。
    try:
        await page.bring_to_front()
    except Exception:
        pass

    # 按当前页面真实 origin 授权（区域可能非 us-east-1），并额外补授 us-east-1 以防万一
    for origin in {_page_origin(page), "https://us-east-1.console.aws.amazon.com"}:
        try:
            await page.context.grant_permissions(
                ["clipboard-read", "clipboard-write"], origin=origin)
        except Exception:
            pass

    copy_selectors = [
        'div[role="dialog"] button:has-text("复制")',
        'div[role="dialog"] button:has-text("Copy")',
        'button:has-text("复制")', 'button:has-text("Copy")',
        'div[role="dialog"] [aria-label*="复制"]',
        'div[role="dialog"] [aria-label*="copy" i]',
    ]

    # 关键：只认「真的含一次性密码（一次性密码: xxx 标签）」的整段信息。建用户是服务端往返，
    # 慢时结果弹窗要 20~40s 才渲染（本批见过 display→下一步就卡了 32s）。所以这里**轮询**
    # 路径 A（复制按钮→剪贴板）+ 路径 B（弹窗 DOM 文本），直到拿到含密码标签的整段、或超时。
    # 不再「等一次没出现就立刻兜底整页文本」——那会把成功提示当密码（见反馈）。
    deadline = time.monotonic() + 45
    raw = ""
    while True:
        # 路径 A：点大「复制/Copy」按钮读剪贴板（一次拿到整段：portal URL + 用户名 + 一次性密码）
        for sel in copy_selectors:
            clip = await _idc_copy_read_raw(page, sel)
            if clip and _extract_otp_by_label(clip):
                raw = clip
                logger.info(f"已抓取整段登录信息（剪贴板, len={len(raw)}）")
                break
        # 路径 B：剪贴板没拿到就读弹窗 DOM 文本（不依赖剪贴板/焦点，最稳）
        if not raw:
            dom = await _idc_read_dialog_text(page)
            if dom and _extract_otp_by_label(dom):
                raw = dom
                logger.info(f"剪贴板未命中，改用弹窗 DOM 文本兜底（len={len(raw)}）")
        if raw or time.monotonic() >= deadline:
            break
        await page.wait_for_timeout(800)

    # 路径 C 末兜底：扫整页文本，但**必须含「一次性密码:」标签**才认。弹窗始终没出现时，
    # 整页里没有该标签 → 宁可判失败人工补录，也绝不拿成功提示/随机 token 冒充密码（见反馈）。
    if not raw:
        try:
            body = (await page.locator("body").inner_text() or "").strip()
            if _extract_otp_by_label(body):
                raw = body
                logger.info(f"弹窗未命中，改用整页文本末兜底（len={len(raw)}）")
        except Exception:
            pass

    if raw:
        await _shot(page, "idc_otp_captured", admin, key=True)
    else:
        logger.warning("未抓到一次性密码（结果弹窗 45s 内始终未出现），看 idc_after_submit 截图人工补录")

    # 关掉弹窗（底部「关闭」/ 右上角 X），避免挡住后续跳转；非关键，关不掉也无妨
    # （warn_on_miss=False：抓不到弹窗时这步必然落空，没必要再刷一条 WARNING）
    await _click_first(page, [
        'button:has-text("关闭")', 'button:has-text("Close")', 'button:has-text("完成")',
        'div[role="dialog"] button[aria-label*="close" i]',
        'div[role="dialog"] button[aria-label*="关闭"]',
    ], "关闭一次性密码弹窗", timeout_ms=2000, warn_on_miss=False)
    return raw


# ── 内部接口抓包（spike）────────────────────────────────────────────────
# 目的：确认控制台「Add user / 生成一次性密码」背后打的是哪个内部接口，
# 拿到 URL / method / 请求体 / 响应体，判断能否绕开浏览器直接调。
# 开启：环境变量 IDC_CAPTURE_API=1（默认关，不影响正常流程）。
# 产出：idc_api_capture_<admin>.jsonl，每行一个 XHR 的请求/响应对。
# 安全：Cookie / Authorization / x-amz-security-token 的值不落盘（只记长度），
#      csrf/token 类头只留前 8 字符做形状参考；请求体/响应体是接口形状，全留。
_IDC_CAPTURE_RE = re.compile(
    r"singlesignon|identitystore|identity-store|userpool|/directory|/users?\b|federat",
    re.I,
)
_CAPTURE_REDACT_FULL = ("cookie", "authorization", "x-amz-security-token")


def _idc_capture_enabled() -> bool:
    return os.environ.get("IDC_CAPTURE_API", "").strip().lower() not in ("", "0", "false", "no")


def _redact_capture_headers(headers: dict) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        kl = k.lower()
        if kl in _CAPTURE_REDACT_FULL:
            out[k] = f"<redacted len={len(v or '')}>"
        elif "csrf" in kl or "token" in kl:
            out[k] = (v[:8] + "…<masked>") if v else v
        else:
            out[k] = v
    return out


async def _attach_idc_api_capture(page: Page, admin: str) -> None:
    """把 singlesignon/identitystore 相关的 XHR/fetch 请求+响应写到 jsonl，供离线分析。"""
    if not _idc_capture_enabled():
        return
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", admin) or "admin"
    path = f"idc_api_capture_{safe}.jsonl"

    async def _on_response(resp) -> None:
        try:
            req = resp.request
            if req.resource_type not in ("xhr", "fetch"):
                return
            url = resp.url
            if not _IDC_CAPTURE_RE.search(url):
                return
            try:
                req_headers = _redact_capture_headers(await req.all_headers())
            except Exception:
                req_headers = {}
            entry = {
                "ts": datetime.datetime.now().isoformat(timespec="seconds"),
                "method": req.method,
                "url": url,
                "status": resp.status,
                "target": req.headers.get("x-amz-target") or req.headers.get("X-Amz-Target"),
                "req_headers": req_headers,
                "req_body": req.post_data,
            }
            try:
                entry["resp_body"] = (await resp.text())[:20000]
            except Exception:
                entry["resp_body"] = None
            with open(path, "a") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.debug(f"IDC API 抓包记录失败: {e}")

    page.on("response", lambda r: asyncio.ensure_future(_on_response(r)))
    logger.info(f"IDC API 抓包已开启 → {path}（IDC_CAPTURE_API=1；记录 singlesignon/identitystore XHR）")


async def aws_idc_open_console(
    context: BrowserContext,
    admin_email: str, admin_password: str, admin_totp: str,
    admin_akid: str, admin_sak: str,
    region: str, instance_id: str,
) -> tuple[Page, str, str]:
    """登录 AWS（admin）并落到 IAM Identity Center，返回 (page, instance_id, start_url)。

    这一段（登录 + 探 instance_id + 读 portal URL）对同一个 admin 只需做一次；批量建多个
    用户时复用返回的 page，避免每个用户都重新登录（--count 的提速点）。
    """
    page = await aws_console_login(
        context, admin_email, admin_password, admin_totp,
        admin_akid, admin_sak,
        destination_url=(f"https://{region}.console.aws.amazon.com/singlesignon/home"
                         f"?region={region}#/instances"),
    )
    await _attach_idc_api_capture(page, admin_email)
    instance_id = await _idc_resolve_instance_id(page, region, instance_id)
    start_url = await _idc_read_portal_url(page, region, instance_id, admin_email)
    return page, instance_id, start_url


async def provision_idc_user_on_page(
    page: Page, admin_email: str,
    region: str, instance_id: str, start_url: str,
    email_domain: str, username_prefix: str, group_name: str,
    username: str = "",
) -> dict:
    """在一个已登录 IDC 的 page 上建 1 个用户并抓整段登录信息。

    不含登录步骤——登录由 aws_idc_open_console 一次性完成。_idc_create_user 内部会先
    goto 到 users 列表页，所以同一 page 连续建多个用户互不干扰。

    username 非空时用作固定用户名（顺序命名 aws1/aws2…由调用方分配）；空则随机命名。

    返回 dict：{username, email, start_url, one_time_password, new_password,
               login_info, group, idc_line, error}
    其中 idc_line 是可直接喂给 `python main.py kiro` 的一行 idc:: 记录。
    """
    user = gen_idc_user(username_prefix, email_domain, username)
    new_password = gen_new_password()
    logger.info(f"建 IDC 用户: username={user['username']} email={user['email']}")
    # login_info = 结果弹窗「复制」抓到的整段登录信息（含 portal URL + 用户名 + 一次性密码）
    login_info = await _idc_create_user(page, region, instance_id, user, admin_email, group_name)
    parsed = _parse_idc_login_info(login_info, username=user["username"])
    one_time_password = parsed["one_time_password"]
    # start_url 优先用复制信息里的（权威），没有再用 dashboard 抓的
    start_url = parsed["start_url"] or start_url

    idc_line = ""
    if start_url and one_time_password:
        idc_line = f"idc::{start_url}----{user['username']}----{one_time_password}----{new_password}"

    return {
        "username": user["username"],
        "email": user["email"],
        "start_url": start_url,
        "one_time_password": one_time_password,
        "new_password": new_password,
        "login_info": login_info,  # 整段登录信息原文，全部保留
        "group": group_name,
        "idc_line": idc_line,
        "error": "",
    }


async def provision_idc_kiro_user(
    context: BrowserContext,
    admin_email: str, admin_password: str, admin_totp: str,
    admin_akid: str, admin_sak: str,
    region: str, instance_id: str,
    email_domain: str, username_prefix: str,
    group_name: str,
) -> dict:
    """完整一次开通（登录 + 建 1 个用户）。薄封装，保留旧调用方式；批量建多个用户请改用
    aws_idc_open_console + provision_idc_user_on_page，避免每个用户重复登录。"""
    page, instance_id, start_url = await aws_idc_open_console(
        context, admin_email, admin_password, admin_totp,
        admin_akid, admin_sak, region, instance_id,
    )
    return await provision_idc_user_on_page(
        page, admin_email, region, instance_id, start_url,
        email_domain, username_prefix, group_name,
    )
