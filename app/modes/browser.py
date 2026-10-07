"""浏览器 mode：chrome —— 单独启动某个 email profile 的真 Chrome，供手动操作/排查登录态。

不挂 ChromeDriver / Playwright / CDP，直接 subprocess 拉起系统真 Chrome.app：
  · Playwright 会被 AWS WAF 抓自动化 instrumentation；
  · Selenium/ChromeDriver 会往页面注入 cdc_ 变量（WAF/Cloudflare 专抓的 ChromeDriver 指纹），
    navigator.webdriver=false 也挡不住；
  · 纯 subprocess 启动＝没有任何自动化，也就没有任何自动化指纹可抓——手动操作场景最干净。
参考 app.core.browser.connect_main_chrome_incognito 里「subprocess 干净启动真 Chrome.app」那段。
"""

import asyncio
import email as email_pkg
import imaplib
import logging
import os
import re
import subprocess
import sys
import time
from email.header import decode_header as _decode_header
from urllib.parse import parse_qs, urlparse

from app.core.browser import _CHROME_APP_BIN, get_kiro_profile_dir
from app.core.imap import imap_delete_uid
from app.settings import BROWSER_LOCALE, BROWSER_TIMEZONE, PROXY

logger = logging.getLogger(__name__)


def _parse_browser_cli_overrides(extra_args: list[str] = None) -> dict:
    """从命令行参数 sys.argv[3:] 解析浏览器指纹/代理覆盖项。

    支持：--tz=Asia/Tokyo  --locale=ja  --os=macos  --geoip=false  --proxy=socks5://host:port
    返回 dict，只含显式指定的 key（未指定的不含，调用方据此判断是否覆盖）。
    """
    args = extra_args if extra_args is not None else sys.argv[3:]
    overrides = {}
    for arg in args:
        if arg.startswith("--tz="):
            overrides["timezone"] = arg.split("=", 1)[1]
        elif arg.startswith("--locale="):
            overrides["locale"] = arg.split("=", 1)[1]
        elif arg.startswith("--os="):
            overrides["os_name"] = arg.split("=", 1)[1]
        elif arg.startswith("--geoip="):
            overrides["geoip"] = arg.split("=", 1)[1].lower() not in ("false", "0", "no", "off")
        elif arg.startswith("--proxy="):
            overrides["proxy"] = arg.split("=", 1)[1]
    return overrides


def _chrome_proxy_args(proxy_url: str) -> list[str]:
    """把代理 URL 转成 Chrome 命令行参数。

    Chrome --proxy-server 不支持内联认证（user:pass@host），只传 scheme://host:port。
    认证代理需用户在 Chrome 弹出的对话框手动输入账密，或使用无认证的代理。
    """
    if not proxy_url:
        return []
    from urllib.parse import urlsplit
    parts = urlsplit(proxy_url)
    scheme = parts.scheme or "http"
    if scheme == "socks5h":
        scheme = "socks5"
    server = f"{scheme}://{parts.hostname}"
    if parts.port:
        server += f":{parts.port}"
    chrome_args = [f"--proxy-server={server}"]
    if parts.username:
        logger.warning("Chrome subprocess 的 --proxy-server 不支持内联认证（user:pass@host），"
                       "认证代理需在 Chrome 弹窗中手动输入账密")
    return chrome_args

# IMAP 收件默认端口（IMAP4_SSL）
_IMAP_DEFAULT_PORT = 993

# 常见邮箱域名 → IMAP 服务器映射（未命中时回退 imap.<domain>）。
# 用于旧格式 email----password 里按域名推断收件服务器；
# 两行显式格式（host:port 换行 email:password）会直接用你给的 host，无需查表。
_IMAP_HOST_MAP = {
    "yahoo.com": "imap.mail.yahoo.com",
    "yahoo.co.jp": "imap.mail.yahoo.co.jp",
    "gmail.com": "imap.gmail.com",
    "googlemail.com": "imap.gmail.com",
    "outlook.com": "outlook.office365.com",
    "hotmail.com": "outlook.office365.com",
    "libero.it": "imapmail.libero.it",
    "nifty.com": "imap.nifty.com",
    "online.de": "imap.1und1.de",
}


def _imap_host_for_domain(domain: str) -> str:
    """按邮箱域名推断 IMAP 服务器；未命中映射表时回退 imap.<domain>。"""
    domain = (domain or "").strip().lower()
    return _IMAP_HOST_MAP.get(domain, f"imap.{domain}" if domain else "")


def _parse_mail_account(raw: str):
    """解析 claude-mail 账号输入，返回 (host, port, email, password)。支持两种格式：

    1) 两行显式 IMAP 服务器（推荐，支持任意邮箱）：
         imap.nifty.com:993
         zwt03656@nifty.com:N3ni12491249
       第一行 host[:port]（port 可省略，默认 993），第二行 email:password
       （也兼容 email----password）。

    2) 单行旧格式（按域名自动推断服务器，主要给 Yahoo）：
         jessica_martin78099@yahoo.com----phvzlvexrxpvhyvg

    解析失败返回 None。
    """
    lines = [ln.strip() for ln in (raw or "").strip().splitlines() if ln.strip()]
    if not lines:
        return None

    host = ""
    port = _IMAP_DEFAULT_PORT
    cred = ""

    # 判定第一行是不是「IMAP 服务器行」：不含 @，且看起来像 host[:port]。
    first = lines[0]
    if "@" not in first and ("." in first.split(":", 1)[0]):
        host_part = first
        if ":" in host_part:
            h, p = host_part.rsplit(":", 1)
            host = h.strip()
            if p.strip().isdigit():
                port = int(p.strip())
            else:  # 冒号不是端口分隔，整行当 host
                host = host_part.strip()
        else:
            host = host_part.strip()
        # 凭据取剩余行里第一条含 @ 的
        cred = next((ln for ln in lines[1:] if "@" in ln), "")
    else:
        # 没有独立服务器行：凭据就在第一条含 @ 的行里，host 后面按域名推断
        cred = next((ln for ln in lines if "@" in ln), "")

    if not cred:
        return None

    # 拆 email 和 password：优先 ----，否则按第一个 : 拆（email 不含 :）
    if "----" in cred:
        email_addr, password = cred.split("----", 1)
    elif ":" in cred:
        email_addr, password = cred.split(":", 1)
    else:
        return None

    email_addr = email_addr.strip()
    password = password.strip()
    if not email_addr or not password or "@" not in email_addr:
        return None

    if not host:
        host = _imap_host_for_domain(email_addr.rsplit("@", 1)[-1])
    if not host:
        return None

    return host, port, email_addr, password


def _parse_mail_account_file(path: str) -> list:
    """解析批量账号文件，返回 [(host, port, email, password), ...]。支持两种布局：

    A) 共享 IMAP 服务器（首行是服务器行，其后每行一个凭据）：
         glacier.mxrouting.net:993
         a@gonaoa.com:pwd1
         b@gonaoa.com:pwd2
       （凭据行 email:password 或 email----password 均可）

    B) 每行一个完整账号（按域名推断服务器）：
         jessica@yahoo.com----appswd
         bob@nifty.com----pwd

    以 # 开头的行和空行忽略。无法解析的行跳过并告警。
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
    except Exception as e:
        logger.error(f"读取账号文件失败: {e}")
        return []

    lines = [ln.strip() for ln in raw_lines if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return []

    # 判定首行是否为「共享 IMAP 服务器行」：不含 @ 且形如 host[:port]
    first = lines[0]
    shared_host_line = ""
    if "@" not in first and ("." in first.split(":", 1)[0]):
        shared_host_line = first
        cred_lines = lines[1:]
    else:
        cred_lines = lines

    accounts = []
    for cred in cred_lines:
        if "@" not in cred:
            continue
        # 共享服务器时，把「服务器行 + 凭据行」拼成两行块复用 _parse_mail_account；
        # 否则单行交给域名推断。
        block = f"{shared_host_line}\n{cred}" if shared_host_line else cred
        parsed = _parse_mail_account(block)
        if parsed:
            accounts.append(parsed)
        else:
            logger.warning(f"跳过无法解析的账号行: {cred}")
    return accounts


async def run_chrome(mode: str, raw_input: str, is_file: bool):
    if is_file:
        print("chrome 模式只接受单个 email/profile 名，不支持文件")
        exit(1)
    # 允许直接粘贴整行账号（email,password / email----password----totp），只取 email 段
    email = re.split(r"----|[,\s]", raw_input.strip())[0].strip()
    if not email:
        print("chrome 模式需要一个 email/profile 名，例如: python main.py chrome 'a@b.com'")
        exit(1)

    if not os.path.exists(_CHROME_APP_BIN):
        print(f"未找到系统 Chrome: {_CHROME_APP_BIN}")
        exit(1)

    extra = sys.argv[3:]
    url = None
    if "--url" in extra:
        i = extra.index("--url")
        if i + 1 >= len(extra):
            print("--url 需要一个地址参数")
            exit(1)
        url = extra[i + 1]

    overrides = _parse_browser_cli_overrides(extra)
    profile_dir = get_kiro_profile_dir(email, browser="realchrome")
    args = [
        _CHROME_APP_BIN,
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    chrome_locale = overrides.get("locale") or BROWSER_LOCALE
    if chrome_locale:
        args.append(f"--lang={chrome_locale}")
    chrome_proxy = overrides.get("proxy") or PROXY
    args.extend(_chrome_proxy_args(chrome_proxy))
    args.append(url or "about:blank")

    chrome_env = None
    chrome_tz = overrides.get("timezone") or BROWSER_TIMEZONE
    if chrome_tz:
        chrome_env = {**os.environ, "TZ": chrome_tz}

    logger.info(f"subprocess 启动真 Chrome（无任何自动化痕迹）profile={profile_dir}"
                f"{f' lang={chrome_locale}' if chrome_locale else ''}"
                f"{f' tz={chrome_tz}' if chrome_tz else ''}"
                f"{f' proxy={chrome_proxy}' if chrome_proxy else ''}")
    logger.info("手动操作浏览器即可；关闭浏览器窗口或 Ctrl+C 退出（登录态保留在 profile 里）")
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=chrome_env)
    try:
        await asyncio.to_thread(proc.wait)
        logger.info("浏览器已关闭")
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("收到中断，正在关闭 Chrome…")
        try:
            proc.terminate()
        except Exception:
            pass


# ============================================================
# claude-mail：纯 chrome 方式打开 claude.ai → Yahoo IMAP 抓登录链接 → 浏览器打开
# ------------------------------------------------------------
# 为什么不用 Playwright：Playwright launch(channel="chrome") 即使去掉 --enable-automation，
# CDP/自动化注入仍会被 claude.ai 的 Cloudflare 抓 → 触发校验。chrome 模式那样「纯
# subprocess 干净启动真 Chrome」零自动化痕迹、不触发校验，本模式完全沿用它。
# 代价：subprocess 没有自动化通道，无法自动填邮箱——邮箱改放剪贴板由人工粘贴提交
# （真人操作最不易触发 Turnstile）。
# 复用：
#   · chrome 方法 → 与 run_chrome 一致的 subprocess 启动（同 --user-data-dir 持久化
#     profile、同参数）；抓到链接后用同 --user-data-dir 再调一次 Chrome，靠 Chrome 单
#     实例机制把 URL 转发给已运行实例，在现有窗口新开 tab 打开；
#   · yahoo 登录 → imap.mail.yahoo.com:993 IMAP4_SSL（同 main.py 的 yahoo 模式）。
# 抓到链接、打开后不关闭浏览器，剩余动作由人工在页面继续操作。
# ============================================================


def _decode_mime_header(raw: str) -> str:
    """解码 MIME 编码的邮件头（Subject / From 等）"""
    parts = []
    for fragment, charset in _decode_header(raw or ""):
        if isinstance(fragment, bytes):
            parts.append(fragment.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(fragment)
    return "".join(parts)


def _extract_email_body(msg) -> str:
    """从 email.message.Message 提取正文（优先 text/html，其次 text/plain）"""
    if msg.is_multipart():
        html = ""
        text = ""
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                body = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ctype == "text/html" and not html:
                html = body
            elif ctype == "text/plain" and not text:
                text = body
        return html or text
    payload = msg.get_payload(decode=True) or b""
    charset = msg.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


def _extract_claude_link(body: str) -> str:
    """从邮件正文中提取 Claude 或 ChatGPT 登录链接（过滤静态资源与跟踪域）"""
    url_re = re.compile(
        r"https://(?:[a-zA-Z0-9_-]+\.)*(?:claude\.ai|claude\.com|anthropic\.com|openai\.com|chatgpt\.com)/[^\s\"'<>()]+",
        re.IGNORECASE,
    )
    # 结尾允许跟 ? 、) 、逗号或字符串结束，避免像 ....woff2) 这类静态资源漏网
    static_re = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js|otf|ttf|woff2?|eot)([?),]|$)", re.IGNORECASE)
    assets_re = re.compile(r"^https://(?:assets|cdn)\.", re.IGNORECASE)
    tracker_re = re.compile(r"^https://[^/]*(?:mail\.anthropic\.com|(?:email|mail|url\d*|t|links?|click)\.openai\.com)/", re.IGNORECASE)
    login_kw = re.compile(r"(sign[-_]?in|magic|verify|auth|login|token|invite|onboard)", re.IGNORECASE)
    # 去掉 URL 尾部可能带的标点（HTML 转义/排版残留）
    matches = [u.rstrip(").,;'\"") for u in url_re.findall(body)]
    candidates = [
        u for u in matches
        if not static_re.search(u) and not assets_re.match(u) and not tracker_re.match(u)
    ]
    if not candidates:
        return ""
    preferred = [u for u in candidates if login_kw.search(u)]
    return preferred[0] if preferred else candidates[0]


def _extract_chatgpt_code(body: str) -> str:
    """从 ChatGPT 验证邮件正文里提取数字验证码（一般 6 位）。取不到返回空串。"""
    # 先去掉 script/style，再剥掉所有 HTML 标签与常见实体，还原成纯文本
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", body or "")
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;|&#\d+;|&[a-zA-Z]+;", " ", text)

    # 优先取「验证码/code/verification/OTP」等关键字附近的数字（窗口内更可靠）
    kw = re.compile(r"(验证码|verification|one[\s-]?time|passcode|\bcode\b|\bOTP\b)", re.IGNORECASE)
    for m in kw.finditer(text):
        window = text[m.end(): m.end() + 40]
        near = re.search(r"(?<!\d)(\d{4,8})(?!\d)", window)
        if near:
            return near.group(1)

    # 兜底：全文里第一个独立的 6 位数字，再退到 4~8 位
    six = re.search(r"(?<!\d)(\d{6})(?!\d)", text)
    if six:
        return six.group(1)
    any_code = re.search(r"(?<!\d)(\d{4,8})(?!\d)", text)
    if any_code:
        return any_code.group(1)

    # 再兜底：验证码被拆成单个数字（HTML 数字框布局，如 "0 1 2 3 4 5"）时，
    # 匹配 4~8 个以空白分隔的单数字，去掉空白拼回
    spaced = re.search(r"(?<!\d)(\d(?:\s+\d){3,7})(?!\d)", text)
    return re.sub(r"\s", "", spaced.group(1)) if spaced else ""


def _imap_latest_uid(host: str, port: int, email_addr: str, app_password: str) -> int:
    """记录触发发信前 INBOX 里的最大 UID，作为「只认新邮件」的基准线。失败返回 0。"""
    try:
        with imaplib.IMAP4_SSL(host, port, timeout=30) as imap:
            imap.login(email_addr, app_password)
            imap.select("INBOX")
            typ, data = imap.uid("search", None, "ALL")
            ids = data[0].split() if typ == "OK" and data and data[0] else []
            return int(ids[-1]) if ids else 0
    except Exception as e:
        logger.warning(f"读取 Yahoo INBOX 基准 UID 失败（按 0 处理）: {e}")
        return 0


def _imap_wait_new_magic_link(host: str, port: int, email_addr: str, app_password: str,
                              baseline_uid: int,
                              timeout_s: int = 180, poll_interval_s: int = 6,
                              sender: str = "anthropic", kind: str = "link",
                              delete: bool = False) -> str:
    """轮询 IMAP，只在 UID 大于 baseline 的新登录邮件里找登录凭据。
    sender 为发件人过滤关键字（claude→anthropic，chatgpt→openai）。
    kind="link" 返回 magic link 完整 URL；kind="code" 返回数字验证码。超时返回空串。
    delete=True 时提取成功后删除命中的那封邮件。"""
    what = "验证码" if kind == "code" else "登录链接"
    logger.info(
        f"开始通过 IMAP {host}:{port} 等待新登录邮件"
        f"（{email_addr}，基准 UID={baseline_uid}，发件人~{sender}，抓取{what}）...")
    end = time.time() + timeout_s
    while time.time() < end:
        try:
            with imaplib.IMAP4_SSL(host, port, timeout=30) as imap:
                imap.login(email_addr, app_password)
                imap.select("INBOX")
                typ, data = imap.uid("search", None, f'(FROM "{sender}")')
                ids = data[0].split() if typ == "OK" and data and data[0] else []
                # 找不到就退回全量，兼容发件域不含 sender 的情况
                if not ids:
                    typ, data = imap.uid("search", None, "ALL")
                    ids = data[0].split() if typ == "OK" and data and data[0] else []
                new_ids = [i for i in ids if int(i) > baseline_uid]
                for uid in reversed(new_ids):  # 最新的优先
                    typ, msg_data = imap.uid("fetch", uid, "(RFC822)")
                    if typ != "OK" or not msg_data or not msg_data[0]:
                        continue
                    msg = email_pkg.message_from_bytes(msg_data[0][1])
                    subject = _decode_mime_header(msg.get("Subject", ""))
                    from_addr = _decode_mime_header(msg.get("From", ""))
                    body = _extract_email_body(msg)
                    if kind == "code":
                        # 验证码可能出现在正文，也可能在主题里，两处都找
                        result = _extract_chatgpt_code(body) or _extract_chatgpt_code(subject)
                    else:
                        result = _extract_claude_link(body)
                    if result:
                        logger.info(f"命中新邮件 UID={uid.decode() if isinstance(uid, bytes) else uid}: "
                                    f"subject={subject[:60]!r} from={from_addr[:50]!r}")
                        logger.info(f"提取到{what}: {result[:120]}")
                        if delete:
                            imap_delete_uid(imap, uid)
                        return result
        except imaplib.IMAP4.error as e:
            logger.warning(f"IMAP 登录/协议错误: {e}")
            return ""
        except Exception as e:
            logger.debug(f"IMAP 轮询异常（继续重试）: {e}")
        time.sleep(poll_interval_s)
    logger.warning(f"等待超时，未抓到新的{what}邮件")
    return ""


def _copy_to_clipboard(text: str) -> bool:
    """把文本放进 macOS 剪贴板（pbcopy）。成功返回 True。"""
    try:
        subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
        return True
    except Exception as e:
        logger.warning(f"复制到剪贴板失败: {e}")
        return False


def _chrome_profile_running(profile_dir: str) -> bool:
    """该 profile 的 Chrome 是否还在运行（按命令行 --user-data-dir=<profile> 精确匹配）。"""
    try:
        r = subprocess.run(
            # 注意 "--" ：pattern 以 "--" 开头，不加分隔符会被 BSD(macOS) pgrep
            # 当成选项解析（illegal option → 退出码 2 → 误判进程已退出）。
            ["pgrep", "-f", "--", f"--user-data-dir={profile_dir}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return r.returncode == 0
    except Exception:
        return False


def _kill_chrome_profile(profile_dir: str) -> None:
    """关闭用该 profile 启动的 Chrome 实例。

    因为 macOS 直接启动 Chrome 二进制时启动进程只是个壳（会 re-exec 后退出），
    拿不到真正 Chrome 的 PID，所以按命令行里的 --user-data-dir=<profile> 精确匹配
    杀进程（只影响这个 profile 的实例，不碰用户其它 Chrome 窗口）。"""
    try:
        subprocess.run(
            # 同 _chrome_profile_running：加 "--" 防止 pattern 被当作选项解析，
            # 否则 macOS 上 pkill 报错、根本没杀掉 Chrome。
            ["pkill", "-f", "--", f"--user-data-dir={profile_dir}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        logger.info(f"已关闭该 profile 的 Chrome: {profile_dir}")
    except Exception as e:
        logger.warning(f"关闭 Chrome 失败: {e}")


def _open_url_in_profile(profile_dir: str, url: str) -> None:
    """用同一 --user-data-dir 再次调用 Chrome 打开 url：Chrome 单实例机制会把 url
    转发给已在运行的那个实例，在现有窗口新开 tab 打开（零自动化痕迹）。"""
    subprocess.Popen(
        [_CHROME_APP_BIN, f"--user-data-dir={profile_dir}", url],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


# 各邮箱登录流程的差异配置：登录页 URL + IMAP 发件人过滤关键字
_MAIL_LOGIN_FLAVORS = {
    "claude-mail": {
        "name": "Claude",
        "login_url": "https://claude.ai/login",
        "sender": "anthropic",
        "continue_btn": "Continue with email",
        "kind": "link",  # Claude 发 magic link，抓到后浏览器直接打开
    },
    "chatgpt-mail": {
        "name": "ChatGPT",
        "login_url": "https://auth.openai.com/log-in",
        "sender": "openai",
        "continue_btn": "Continue",
        "kind": "code",  # ChatGPT 发数字验证码，抓到后进剪贴板由你粘贴
    },
}


async def run_chatgpt_mail(mode: str, raw_input: str, is_file: bool):
    """chatgpt-mail：与 claude-mail 完全相同的纯 chrome + IMAP 抓登录链接流程，
    只是打开 ChatGPT 登录页、按 openai 发件人过滤邮件。用法同 claude-mail。"""
    await run_claude_mail(mode, raw_input, is_file)


async def run_claude_mail(mode: str, raw_input: str, is_file: bool):
    """纯 chrome 方式（subprocess 启动真 Chrome，零自动化痕迹，不触发校验）：
    打开 claude.ai / ChatGPT 登录页 → 邮箱进剪贴板由你手动粘贴提交 → 后台 IMAP 抓
    最新登录链接 → 用同 profile 的 Chrome 自动在现有窗口打开链接，随后保留页面手动操作。

    mode 为 claude-mail（打开 claude.ai，抓 anthropic 邮件）或
    chatgpt-mail（打开 auth.openai.com，抓 openai 邮件）。

    支持任意 IMAP 服务器，两种输入格式：

    1) 两行显式 IMAP 服务器（推荐，支持任意邮箱）：
         imap.nifty.com:993
         zwt03656@nifty.com:N3ni12491249
       第一行 host[:port]（port 默认 993），第二行 email:password（也兼容 ----）。
       例: python main.py claude-mail $'imap.nifty.com:993\\nzwt03656@nifty.com:N3ni12491249'

    2) 单行旧格式（按域名自动推断服务器）：
         python main.py claude-mail 'jessica_martin78099@yahoo.com----phvzlvexrxpvhyvg'

    默认抓到登录链接/验证码后把那封邮件从收件箱删除；加 --keep 则保留。
    """
    flavor = _MAIL_LOGIN_FLAVORS.get(mode, _MAIL_LOGIN_FLAVORS["claude-mail"])
    delete_after = "--keep" not in sys.argv[3:]
    if is_file:
        print(f"{mode} 模式只接受单条账号，不支持文件")
        exit(1)

    parsed = _parse_mail_account(raw_input)
    if not parsed:
        print("账号格式错误。支持两种格式：")
        print("  1) 两行: 第一行 host[:port]，第二行 email:password")
        print("       imap.nifty.com:993")
        print("       zwt03656@nifty.com:N3ni12491249")
        print("  2) 单行: email----app_password（按域名推断服务器）")
        exit(1)

    imap_host, imap_port, email_addr, app_password = parsed
    # Yahoo 应用专用密码带空格，去掉；其他服务器密码保留原样
    if "yahoo" in imap_host.lower():
        app_password = app_password.replace(" ", "")

    if not os.path.exists(_CHROME_APP_BIN):
        print(f"未找到系统 Chrome: {_CHROME_APP_BIN}")
        exit(1)

    overrides = _parse_browser_cli_overrides()
    logger.info(f"IMAP 收件服务器: {imap_host}:{imap_port}（{email_addr}）")
    profile_dir = get_kiro_profile_dir(email_addr, browser="realchrome")

    # 记录发信前的收件箱基准 UID，确保只认之后到达的新登录邮件
    baseline_uid = await asyncio.to_thread(
        _imap_latest_uid, imap_host, imap_port, email_addr, app_password)
    logger.info(f"收件箱基准 UID={baseline_uid}（只抓此后到达的新邮件）")

    # subprocess 干净启动真 Chrome（与 chrome 模式完全一致的启动方式，零自动化痕迹）
    args = [
        _CHROME_APP_BIN,
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    chrome_locale = overrides.get("locale") or BROWSER_LOCALE
    if chrome_locale:
        args.append(f"--lang={chrome_locale}")
    chrome_proxy = overrides.get("proxy") or PROXY
    args.extend(_chrome_proxy_args(chrome_proxy))
    args.append(flavor["login_url"])

    chrome_env = None
    chrome_tz = overrides.get("timezone") or BROWSER_TIMEZONE
    if chrome_tz:
        chrome_env = {**os.environ, "TZ": chrome_tz}

    logger.info(f"subprocess 启动真 Chrome（无任何自动化痕迹）profile={profile_dir}"
                f"{f' lang={chrome_locale}' if chrome_locale else ''}"
                f"{f' tz={chrome_tz}' if chrome_tz else ''}"
                f"{f' proxy={chrome_proxy}' if chrome_proxy else ''}")
    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     env=chrome_env)

    # 邮箱放进剪贴板，提示手动粘贴提交（真人操作，最不易触发 Cloudflare 校验）
    copied = _copy_to_clipboard(email_addr)
    print("\n" + "=" * 60)
    print(f"账号: {email_addr}")
    if copied:
        print(f"邮箱已复制到剪贴板。请在 {flavor['name']} 登录页的邮箱框粘贴（Cmd+V），")
        print(f"然后点『{flavor['continue_btn']}』提交，触发 {flavor['name']} 发送登录邮件。")
    else:
        print(f"请在 {flavor['name']} 登录页手动输入邮箱：{email_addr}")
        print(f"然后点『{flavor['continue_btn']}』提交，触发 {flavor['name']} 发送登录邮件。")
    is_code = flavor["kind"] == "code"
    if is_code:
        print("提交后无需切窗，程序会在后台自动抓取验证码并复制到剪贴板，你粘贴到页面即可。")
    else:
        print("提交后无需切窗，程序会在后台自动抓取登录链接并在浏览器打开。")
    print("=" * 60 + "\n")

    # 后台轮询 IMAP 抓新登录凭据（放宽超时给手动提交留时间）
    result = await asyncio.to_thread(
        _imap_wait_new_magic_link, imap_host, imap_port, email_addr, app_password,
        baseline_uid, 300, 6, flavor["sender"], flavor["kind"], delete_after
    )

    if result and is_code:
        # ChatGPT：验证码进剪贴板，直接打印，由你粘贴到已打开的登录页
        copied_code = _copy_to_clipboard(result)
        print("\n" + "=" * 60)
        print(f"验证码: {result}")
        if copied_code:
            print("验证码已复制到剪贴板，请在登录页粘贴（Cmd+V）提交。")
        else:
            print("请手动把上面的验证码输入登录页提交。")
        print("=" * 60 + "\n")
    elif result:
        # Claude：magic link 用同 profile 的 Chrome 在现有窗口打开
        logger.info("抓到登录链接，用同 profile 的 Chrome 在现有窗口打开...")
        try:
            _open_url_in_profile(profile_dir, result)
            print(f"\n已在浏览器打开登录链接:\n{result}\n")
        except Exception as e:
            logger.warning(f"自动打开失败: {e}")
            print(f"\n自动打开失败，请手动复制到浏览器打开:\n{result}\n")
    else:
        what = "验证码" if is_code else "登录链接"
        print(f"\n未抓到{what}。可能邮件未到、未提交邮箱或解析失败。")
        print("浏览器保持打开，可手动检查邮箱后在页面继续操作。\n")

    # 对齐 chrome 模式的退出体验：关掉浏览器窗口程序就自动退出。
    # claude-mail 因为抓到链接后又第二次启动 Chrome 转发 URL（_open_url_in_profile），
    # 会打断第一个 proc 句柄，所以不用 proc.wait()，改成轮询该 profile 的 Chrome 是否还在：
    #   · 手动关掉浏览器窗口 → 进程消失 → 程序退出（登录态保留在 profile 里）
    #   · Ctrl+C → 主动关闭该 profile 的 Chrome 后退出
    logger.info("剩余动作请在浏览器中手动完成；关闭浏览器窗口或 Ctrl+C 退出（登录态保留在 profile 里）")
    try:
        while _chrome_profile_running(profile_dir):
            await asyncio.sleep(2)
        logger.info("浏览器已关闭")
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("收到中断，正在关闭 Chrome…")
        _kill_chrome_profile(profile_dir)


# ============================================================
# claude-email：Camoufox 自动化浏览器方式的邮箱 magic link 登录
# ------------------------------------------------------------
# 与 claude-mail（subprocess 真 Chrome）的区别：
#   · Camoufox stealth Firefox 自动化 —— 可以自动填邮箱、提交、打开 magic link、
#     推进注册引导、提取 sessionKey，全流程无需手动干预
#   · 正常自动化登录不触发 SMS 验证（subprocess Chrome 反而会触发）
#   · 代价：自动化浏览器理论上可被 Cloudflare 检测，但 Camoufox 过率通常较高
# ============================================================


def _extract_oauth_code_from_url(url: str, pending_state: str) -> str | None:
    """从 OAuth 回跳 URL 里提取授权码，拼成 exchange 需要的 `code#state` 格式。

    只认 callback/oauth/code 回跳页，避免把授权页自身的 code=true 误当成授权码。
    """
    try:
        parts = urlparse(url)
    except Exception:
        return None
    path = (parts.path or "").lower()
    if "callback" not in path and "oauth/code" not in path:
        return None
    qs = parse_qs(parts.query)
    code = (qs.get("code") or [None])[0]
    if not code or code in ("true", "false") or len(code) < 8:
        return None
    if "#" in code:
        return code
    state = (qs.get("state") or [None])[0] or pending_state
    return f"{code}#{state}"


async def _extract_oauth_code_from_page(page, pending_state: str) -> str | None:
    """兜底：从「复制授权码」页面的输入框或正文里提取 `code#pending_state`。"""
    try:
        inputs = page.locator('input[readonly], input[type="text"]')
        n = await inputs.count()
        for i in range(min(n, 6)):
            try:
                val = (await inputs.nth(i).input_value()) or ""
            except Exception:
                continue
            if "#" in val and pending_state in val:
                return val.strip()
        body = await page.content()
    except Exception:
        return None
    m = re.search(r"([A-Za-z0-9_\-]{10,}#%s)" % re.escape(pending_state), body)
    return m.group(1) if m else None


async def _oauth_authorize_and_capture(page, auth_url: str, pending_state: str,
                                       email_addr: str, screenshot_path) -> str | None:
    """在已登录 Claude 的页面打开授权链接 → 点 Authorize → 抓回跳的授权码。"""
    logger.info(f"打开授权链接: {auth_url}")
    await page.goto(auth_url, wait_until="domcontentloaded")
    await page.wait_for_timeout(2000)
    await page.screenshot(path=screenshot_path("bind_authorize", email_addr))

    authorize_btn = (
        'button:has-text("Authorize"), button:has-text("授权"), '
        'button:has-text("Allow"), button:has-text("Approve"), '
        'button:has-text("Continue"), a:has-text("Authorize")'
    )
    for i in range(90):  # 最长约 180s
        # 1) 回跳 URL 里直接带 code
        code = _extract_oauth_code_from_url(page.url, pending_state)
        if code:
            logger.info("已从回跳 URL 抓到授权码")
            return code
        # 2) 复制授权码页面
        code = await _extract_oauth_code_from_page(page, pending_state)
        if code:
            logger.info("已从页面抓到授权码")
            return code
        # 3) 点授权按钮（已跳到 callback 后页面上不会再有，自然跳过）
        try:
            btn = page.locator(authorize_btn)
            if await btn.count() > 0 and await btn.first.is_visible():
                await btn.first.click()
                logger.info("已点击授权按钮")
                await page.wait_for_timeout(2500)
                continue
        except Exception:
            pass
        await page.wait_for_timeout(2000)
    await page.screenshot(path=screenshot_path("bind_no_code", email_addr))
    return None


async def _bind_account_to_backend(page, email_addr: str, screenshot_path,
                                   admin_token: str = None) -> bool:
    """claude-email 登录成功后：拉授权链接 → 浏览器授权 → exchange 落库。返回是否成功。

    admin_token: 命令行 --admin-token= 传入的后台 access_token（非 vendor 账号），
    优先级高于 config 里的 OAUTH_ADMIN_API_TOKEN / REFRESH_TOKEN。
    """
    from app.accounts import oauth_bind

    tok_kw = {"token": admin_token} if admin_token else {}
    try:
        auth_url, pending_state = await asyncio.to_thread(
            lambda: oauth_bind.get_auth_url(**tok_kw))
    except Exception as e:
        logger.error(f"获取授权链接失败: {e}")
        print(f"\n[bind] 获取授权链接失败: {e}\n")
        return False
    logger.info(f"pending_state={pending_state}")

    code = await _oauth_authorize_and_capture(page, auth_url, pending_state, email_addr, screenshot_path)
    if not code:
        logger.warning("未抓到授权码，跳过 exchange")
        print("\n[bind] 未抓到授权码（可能授权页结构变化或未完成授权），浏览器保留可手动完成。\n")
        return False
    logger.info(f"授权码: {code[:12]}...#{pending_state}")

    try:
        result = await asyncio.to_thread(
            lambda: oauth_bind.exchange(code, pending_state, **tok_kw))
    except Exception as e:
        logger.error(f"exchange 失败: {e}")
        print(f"\n[bind] exchange 失败: {e}\n")
        return False

    logger.info(f"exchange 成功: {result}")
    data = result.get("data") if isinstance(result.get("data"), dict) else result
    print("\n" + "=" * 60)
    print(f"[bind] 账号已加入后台: {email_addr}")
    # 兼容两种后端：default 多为 name/email；luban 为 label/tier
    name = (data.get("name") or data.get("email") or data.get("label") or "")
    acc_id = data.get("id", "")
    tier = data.get("tier") or ""
    if name:
        print(f"       name={name}")
    if acc_id != "":
        print(f"       id={acc_id}")
    if tier:
        print(f"       tier={tier}")
    print("=" * 60 + "\n")
    return True


async def _claude_profile_logged_in(page, context) -> bool:
    """判断当前 profile 是否已登录 claude.ai：打开 /new，被弹回 /login 即未登录；
    停在 /new|/chat 且有 sessionKey cookie 即已登录。"""
    try:
        await page.goto("https://claude.ai/new", wait_until="domcontentloaded")
    except Exception:
        return False
    for _ in range(8):
        cur = page.url
        if "/login" in cur:
            return False
        try:
            cookies = await context.cookies("https://claude.ai")
        except Exception:
            cookies = []
        has_key = any(c.get("name") == "sessionKey" and c.get("value") for c in cookies)
        if has_key and ("claude.ai/new" in cur or "claude.ai/chat" in cur):
            return True
        await page.wait_for_timeout(1500)
    return False


async def _claude_extract_session_and_bind(page, context, email_addr, app_password,
                                           bind_after, admin_token, screenshot_path):
    """提取 sessionKey（写入 session.txt），需要时再执行加入后台。已登录/新登录两条路径共用。"""
    logger.info(f"最终页面: {page.url}")
    try:
        await page.screenshot(path=screenshot_path("email_final", email_addr))
    except Exception:
        pass

    cookies = await context.cookies("https://claude.ai")
    session_key = None
    for cookie in cookies:
        if cookie["name"] == "sessionKey":
            session_key = cookie["value"]
            break

    if session_key:
        logger.info(f"登录成功！sessionKey: {session_key[:20]}...")
        with open("session.txt", "a") as f:
            f.write(f"{email_addr}----{app_password}----{session_key}\n")
        logger.info("已保存到 session.txt")
    else:
        logger.warning("未找到 sessionKey，请检查截图")

    # bind：登录成功（已拿到 sessionKey）后，把账号通过 OAuth 授权加入后台
    if bind_after:
        if session_key:
            logger.info("开始把账号加入 oauth-accounts 后台...")
            await _bind_account_to_backend(page, email_addr, screenshot_path, admin_token)
        else:
            logger.warning("未登录成功（无 sessionKey），跳过加入后台")
            print("\n[bind] 未登录成功，跳过加入后台。\n")
    return session_key


async def run_claude_email(mode: str, raw_input: str, is_file: bool):
    """Camoufox 自动化浏览器方式登录 Claude（邮箱 magic link）。

    流程：Camoufox 打开 claude.ai/login → 自动填邮箱并提交 → 后台 IMAP 抓 magic link
    → 同一 context 内导航到 magic link → 自动推进注册引导 → 提取 sessionKey。

    单条输入格式同 claude-mail：
      1) 两行: host[:port] 换行 email:password
      2) 单行: email----app_password（按域名推断服务器）

    批量：传入文件路径即批量处理（claude-email / claude-bind 均支持）。文件两种布局：
      A) 首行 IMAP 服务器，其后每行 email:password（共享服务器，推荐同邮箱域批量）
      B) 每行一个 email----app_password（按域名推断服务器）

    claude-bind 模式（或 claude-email 加 --bind）：登录成功后，自动拉授权链接、
    在同一浏览器完成 OAuth 授权，并调用后台 exchange 把账号加入 oauth-accounts。
    """
    delete_after = "--keep" not in sys.argv[3:]
    bind_after = mode == "claude-bind" or "--bind" in sys.argv[3:]
    admin_token = next((a.split("=", 1)[1] for a in sys.argv[3:]
                        if a.startswith("--admin-token=")), None)
    overrides = _parse_browser_cli_overrides()

    # 批量：文件输入
    if is_file:
        accounts = _parse_mail_account_file(raw_input)
        if not accounts:
            print("文件中未解析到有效账号。支持两种文件格式：")
            print("  A) 首行 IMAP 服务器，其后每行 email:password（或 email----password）：")
            print("       glacier.mxrouting.net:993")
            print("       a@gonaoa.com:pwd1")
            print("       b@gonaoa.com:pwd2")
            print("  B) 每行一个 email----app_password（按域名推断服务器）")
            exit(1)
        total = len(accounts)
        logger.info(f"批量模式：共 {total} 个账号")
        ok = 0
        for idx, (imap_host, imap_port, email_addr, app_password) in enumerate(accounts, 1):
            logger.info(f"========== [{idx}/{total}] {email_addr} ==========")
            try:
                await _run_claude_email_single(
                    imap_host, imap_port, email_addr, app_password,
                    delete_after=delete_after, bind_after=bind_after,
                    admin_token=admin_token, overrides=overrides, interactive=False)
                ok += 1
            except Exception as e:
                logger.error(f"[{idx}/{total}] {email_addr} 处理失败: {e}")
        logger.info(f"批量完成：成功 {ok}/{total}（失败 {total - ok}）")
        return

    # 单条
    parsed = _parse_mail_account(raw_input)
    if not parsed:
        print("账号格式错误。支持两种格式：")
        print("  1) 两行: 第一行 host[:port]，第二行 email:password")
        print("       imap.nifty.com:993")
        print("       zwt03656@nifty.com:N3ni12491249")
        print("  2) 单行: email----app_password（按域名推断服务器）")
        print("  （批量：直接传文件路径，见 claude-email --help）")
        exit(1)
    imap_host, imap_port, email_addr, app_password = parsed
    await _run_claude_email_single(
        imap_host, imap_port, email_addr, app_password,
        delete_after=delete_after, bind_after=bind_after,
        admin_token=admin_token, overrides=overrides, interactive=True)


async def _run_claude_email_single(imap_host, imap_port, email_addr, app_password, *,
                                   delete_after, bind_after, admin_token, overrides,
                                   interactive=True):
    """对单个账号执行 claude-email / claude-bind 全流程。

    interactive=False（批量时）：账号间不暂停等回车，出错由上层捕获后继续下一个。
    """
    if "yahoo" in imap_host.lower():
        app_password = app_password.replace(" ", "")

    logger.info(f"IMAP 收件服务器: {imap_host}:{imap_port}（{email_addr}）")

    from app.core.browser import (
        get_kiro_profile_dir,
        human_delay,
        launch_camoufox_persistent_context,
        close_camoufox_persistent_context,
        screenshot_path as _screenshot_path,
    )
    from app.accounts.claude import _claude_advance_onboarding

    baseline_uid = await asyncio.to_thread(
        _imap_latest_uid, imap_host, imap_port, email_addr, app_password)
    logger.info(f"收件箱基准 UID={baseline_uid}")

    # 用持久化 context（按邮箱账号隔离 profile），cookie 跨 tab/跨次复用
    profile_dir = get_kiro_profile_dir(email_addr, browser="firefox")
    context, cm = await launch_camoufox_persistent_context(
        profile_dir,
        locale=overrides.get("locale"),
        timezone=overrides.get("timezone"),
        os_name=overrides.get("os_name"),
        geoip=overrides.get("geoip"),
    )
    try:
        try:
            page = context.pages[0] if context.pages else await context.new_page()

            # 0. 已登录检测：该 profile 已登录 claude 则跳过整个邮箱 magic link 登录，
            #    直接提取 sessionKey（并按需加入后台）。
            logger.info("检测该 profile 是否已登录 Claude...")
            if await _claude_profile_logged_in(page, context):
                logger.info("该 profile 已登录 Claude，跳过邮箱登录流程")
                await _claude_extract_session_and_bind(
                    page, context, email_addr, app_password,
                    bind_after, admin_token, _screenshot_path)
                if interactive and sys.stdin.isatty():
                    try:
                        input("流程结束，按回车键关闭浏览器...")
                    except (EOFError, KeyboardInterrupt):
                        pass
                return

            # 1. 打开 Claude 登录页
            logger.info("正在打开 claude.ai/login...")
            await page.goto("https://claude.ai/login", wait_until="domcontentloaded")
            await human_delay(page, "navigate")
            await page.screenshot(path=_screenshot_path("email_landing", email_addr))

            # 2. 等待邮箱输入框出现并填写
            #    claude.ai/login 页面布局：Google / Apple / OR / 邮箱输入框 / Continue with email
            #    输入框和提交按钮同屏显示，无需先点击展开
            email_input = page.locator(
                'input[type="email"], input[name="email"], '
                'input[placeholder*="email" i], input[placeholder*="Email" i]'
            )
            for _ in range(15):
                if await email_input.count() > 0 and await email_input.first.is_visible():
                    break
                await page.wait_for_timeout(1000)
            if await email_input.count() > 0:
                await email_input.first.fill(email_addr)
                await human_delay(page, "type")
                logger.info(f"已填写邮箱: {email_addr}")
            else:
                logger.error("未找到邮箱输入框")
                await page.screenshot(path=_screenshot_path("email_no_input", email_addr))
                if interactive and sys.stdin.isatty():
                    input("未找到邮箱输入框，按回车键关闭浏览器...")
                return

            # 3. 点击 "Continue with email"（严格匹配，避免误点 Google/Apple）
            submit_btn = page.locator(
                'button:has-text("Continue with email"), '
                'button:has-text("Continue with login link")'
            )
            for _ in range(5):
                if await submit_btn.count() > 0 and await submit_btn.first.is_visible():
                    break
                await page.wait_for_timeout(1000)
            if await submit_btn.count() > 0:
                await submit_btn.first.click()
                await human_delay(page, "click")
                logger.info("已点击 'Continue with email'")
            else:
                logger.warning("未找到 'Continue with email'，尝试 type=submit 兜底")
                fallback = page.locator('button[type="submit"]')
                if await fallback.count() > 0:
                    await fallback.first.click()
                    await human_delay(page, "click")
            await page.screenshot(path=_screenshot_path("email_submitted", email_addr))

            # 5. 后台 IMAP 轮询抓 magic link
            logger.info("等待登录邮件（最长 5 分钟）...")
            magic_link = await asyncio.to_thread(
                _imap_wait_new_magic_link, imap_host, imap_port, email_addr, app_password,
                baseline_uid, 300, 6, "anthropic", "link", delete_after,
            )

            if not magic_link:
                logger.warning("未抓到登录链接")
                await page.screenshot(path=_screenshot_path("email_no_link", email_addr))
                if interactive and sys.stdin.isatty():
                    input("未抓到登录链接，按回车键关闭浏览器...")
                return

            # 6. 在原页面打开 magic link（同一 context，cookie 共享）
            logger.info(f"抓到登录链接，在原页面打开...")
            await page.goto(magic_link, wait_until="domcontentloaded")
            await human_delay(page, "navigate")
            await page.screenshot(path=_screenshot_path("email_magic_link", email_addr))

            # 7. 等待登录完成 + 自动推进注册引导
            last_url = ""
            unrecognized_streak = 0
            manual_warned = False
            for i in range(120):
                await page.wait_for_timeout(3000)
                current_url = page.url
                if "claude.ai/new" in current_url or "claude.ai/chat" in current_url:
                    logger.info(f"已进入 Claude 对话页面！URL: {current_url}")
                    break

                if current_url != last_url:
                    logger.info(f"等待登录完成... ({(i+1)*3}s) URL: {current_url}")
                    last_url = current_url

                try:
                    action = await _claude_advance_onboarding(page, email_addr)
                except Exception as e:
                    logger.debug(f"onboarding 推进异常: {e}")
                    action = ""
                if action:
                    logger.info(f"自动通过注册引导: {action}")
                    unrecognized_streak = 0
                    continue

                terms_btn = page.locator(
                    'button:has-text("Accept"), button:has-text("Agree"), '
                    'button:has-text("接受"), button:has-text("同意")'
                )
                if await terms_btn.count() > 0 and await terms_btn.first.is_visible():
                    await terms_btn.first.click()
                    await human_delay(page, "click")
                    unrecognized_streak = 0
                    continue

                # 仍停留在 signup/onboarding 但识别不出来 → 截图+日志（便于排查）
                if "signup" in current_url or "register" in current_url or "onboarding" in current_url:
                    unrecognized_streak += 1
                    if unrecognized_streak == 3 and not manual_warned:
                        logger.warning(
                            f"⚠️  未识别的注册/引导页面 URL={current_url}，已截图 "
                            f"claude_needs_manual_*，继续等待（共 {(i+1)*3}s）"
                        )
                        await page.screenshot(
                            path=_screenshot_path("claude_needs_manual", email_addr))
                        try:
                            btn_texts = await page.locator("button").all_inner_texts()
                            visible_btns = [t.strip() for t in btn_texts if t.strip()]
                            logger.warning(f"   当前页面按钮文案: {visible_btns}")
                        except Exception as e:
                            logger.debug(f"收集按钮文案失败: {e}")
                        manual_warned = True
                    # 每 30s 再补一张，观察页面是否有变化
                    elif unrecognized_streak % 10 == 0:
                        await page.screenshot(
                            path=_screenshot_path(
                                f"claude_needs_manual_{unrecognized_streak*3}s", email_addr))

            # 8. 提取 sessionKey（并按需加入后台）
            await _claude_extract_session_and_bind(
                page, context, email_addr, app_password,
                bind_after, admin_token, _screenshot_path)

        except Exception as e:
            logger.error(f"执行过程中出错: {e}")
            try:
                for i, pg in enumerate(context.pages):
                    await pg.screenshot(path=_screenshot_path(f"email_error_{i}", email_addr))
            except Exception:
                pass

        if interactive and sys.stdin.isatty():
            try:
                input("流程结束，按回车键关闭浏览器...")
            except (EOFError, KeyboardInterrupt):
                pass
    finally:
        await close_camoufox_persistent_context(cm)
