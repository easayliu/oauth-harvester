"""email 模式：通过 MXroute API 增删/查询邮箱账号。

用法：
  python main.py email add  user@domain.com Password123 [--quota N] [--limit N]
  python main.py email add  user Password123 --domain domain.com
  python main.py email add  accounts.txt            # 批量，每行 email----password
  python main.py email add  --random 10 --domain domain.com --out new.txt  # 随机生成 10 个
  python main.py email del  user@domain.com
  python main.py email del  accounts.txt            # 批量，每行 email（或 email----...）
  python main.py email list [domain.com]
  python main.py email inbox user@domain.com----Password123 [--count N] [--search 'FROM anthropic'] [--keep]

未显式给域名时，取 --domain，再退回 config.MXROUTE_DEFAULT_DOMAIN。
inbox 用 IMAP 登录 config.MXROUTE_SERVER:993 读信并抓 claude.ai 链接；
默认删除抓到链接的邮件，加 --keep 保留。
"""

import base64
import email as email_pkg
import html as html_pkg
import imaplib
import logging
import os
import re
import secrets
import string
import sys
from email.header import decode_header as _decode_header

from app.core.imap import imap_delete_uid
from app.accounts.mxroute import (
    MXRouteError,
    create_email_account,
    delete_email_account,
    list_email_accounts,
    split_email,
)
from app.settings import (
    MXROUTE_DEFAULT_DOMAIN,
    MXROUTE_DEFAULT_LIMIT,
    MXROUTE_DEFAULT_QUOTA,
    MXROUTE_SERVER,
)

logger = logging.getLogger(__name__)


def _pop_opt(extra: list, name: str, default=None):
    """从参数列表里取 --name <value>，取到就从 extra 中移除，返回值。"""
    if name in extra:
        i = extra.index(name)
        if i + 1 < len(extra):
            val = extra[i + 1]
            del extra[i:i + 2]
            return val
        del extra[i:i + 1]
    return default


def _load_lines(raw_input: str, is_file: bool) -> list:
    """文件→非空非注释行；否则把单条输入当一行。"""
    if is_file:
        with open(raw_input, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = raw_input
    lines = []
    for ln in content.splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines


_NAME_ONSETS = [
    "b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t",
    "v", "w", "br", "cr", "dr", "fr", "gr", "kr", "pr", "tr", "bl", "cl", "fl",
    "gl", "pl", "sl", "st", "sp", "sk", "sw", "kw", "ch", "sh", "th",
]
_NAME_VOWELS = ["a", "e", "i", "o", "u", "ai", "ea", "ee", "oo", "ou", "ow"]
_NAME_CODAS = ["", "", "", "n", "m", "r", "s", "l", "t", "d", "ne", "ng", "nd", "rt"]


def _rand_name_part(target_len: int) -> str:
    """生成一个可发音、像人名的字母串（纯小写字母，无数字）。"""
    target_len = max(target_len, 3)
    part = secrets.choice(_NAME_ONSETS) + secrets.choice(_NAME_VOWELS)
    # 按音节拼接直到接近目标长度
    while len(part) < target_len:
        part += secrets.choice(_NAME_ONSETS) + secrets.choice(_NAME_VOWELS)
    part += secrets.choice(_NAME_CODAS)
    return part[: max(target_len, 4)] if len(part) > target_len + 2 else part


def _rand_username(length: int = 10) -> str:
    """随机邮箱本地部分：两段可发音的类人名，用点连接，如 kwone.cosnw。"""
    length = max(length, 6)
    # 在两段之间分配长度（点号占 1 位）
    first_len = max((length - 1) // 2, 3)
    second_len = max(length - 1 - first_len, 3)
    return f"{_rand_name_part(first_len)}.{_rand_name_part(second_len)}"


def _rand_password(length: int = 14) -> str:
    """随机密码：保证含大小写字母+数字（满足 MXroute 规则），无易混淆歧义字符。"""
    length = max(length, 8)
    lowers = "abcdefghijkmnpqrstuvwxyz"   # 去掉 l/o
    uppers = "ABCDEFGHJKLMNPQRSTUVWXYZ"   # 去掉 I/O
    digits = "23456789"                   # 去掉 0/1
    pool = lowers + uppers + digits
    chars = [
        secrets.choice(lowers),
        secrets.choice(uppers),
        secrets.choice(digits),
    ]
    chars += [secrets.choice(pool) for _ in range(length - 3)]
    # 打乱，避免固定位置
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)


def _parse_record(line: str) -> tuple:
    """把一行拆成 (email, password)。支持分隔符 ---- 或空白/竖线。"""
    for sep in ("----", "|", "\t"):
        if sep in line:
            parts = [p.strip() for p in line.split(sep) if p.strip()]
            email = parts[0] if parts else ""
            password = parts[1] if len(parts) > 1 else ""
            return email, password
    parts = line.split()
    email = parts[0] if parts else ""
    password = parts[1] if len(parts) > 1 else ""
    return email, password


async def run_email(mode: str, raw_input: str, is_file: bool):
    # raw_input 是子命令 add/del/list；真正的目标在 sys.argv[3:] 里
    sub = (raw_input or "").lower()
    extra = list(sys.argv[3:])

    domain_opt = _pop_opt(extra, "--domain", "")
    quota_opt = _pop_opt(extra, "--quota")
    limit_opt = _pop_opt(extra, "--limit")
    random_opt = _pop_opt(extra, "--random")
    out_opt = _pop_opt(extra, "--out")
    user_len_opt = _pop_opt(extra, "--user-len")
    pass_len_opt = _pop_opt(extra, "--pass-len")

    def resolve_domain(explicit: str = "") -> str:
        return explicit or domain_opt or MXROUTE_DEFAULT_DOMAIN

    try:
        if sub in ("add", "create", "new"):
            await _run_add(extra, resolve_domain, quota_opt, limit_opt,
                           random_opt, out_opt, user_len_opt, pass_len_opt)
        elif sub in ("del", "delete", "rm", "remove"):
            await _run_del(extra, resolve_domain)
        elif sub in ("list", "ls"):
            await _run_list(extra, resolve_domain)
        elif sub in ("inbox", "imap", "read"):
            await _run_inbox(extra)
        else:
            print("email 子命令需为 add / del / list / inbox，例如：")
            print("  python main.py email add user@domain.com Password123")
            print("  python main.py email del user@domain.com")
            print("  python main.py email list domain.com")
            print("  python main.py email inbox user@domain.com----Password123")
            exit(1)
    except MXRouteError as e:
        print(f"MXroute 错误 [{e.status} {e.code}]: {e}")
        exit(1)


async def _run_add(extra, resolve_domain, quota_opt, limit_opt,
                   random_opt=None, out_opt=None, user_len_opt=None, pass_len_opt=None):
    quota = int(quota_opt) if quota_opt is not None else MXROUTE_DEFAULT_QUOTA
    limit = int(limit_opt) if limit_opt is not None else MXROUTE_DEFAULT_LIMIT
    user_len = int(user_len_opt) if user_len_opt is not None else 10
    pass_len = int(pass_len_opt) if pass_len_opt is not None else 14

    records = []

    if random_opt is not None:
        # 随机生成 N 个邮箱：本地部分随机，密码随机（满足规则）
        try:
            count = int(random_opt)
        except ValueError:
            print(f"--random 需要一个整数，got: {random_opt}")
            exit(1)
        if count < 1:
            print("--random 数量需 >= 1")
            exit(1)
        domain = resolve_domain()
        if not domain:
            print("随机生成需要域名：加 --domain domain.com 或配置 MXROUTE_DEFAULT_DOMAIN")
            exit(1)
        seen = set()
        while len(records) < count:
            local = _rand_username(user_len)
            if local in seen:
                continue
            seen.add(local)
            records.append((f"{local}@{domain}", _rand_password(pass_len)))
    else:
        # 判断第一个位置参数是不是文件（批量）
        target = extra[0] if extra else ""
        is_file = bool(target) and os.path.isfile(target)
        if is_file:
            for line in _load_lines(target, True):
                email, password = _parse_record(line)
                if email and password:
                    records.append((email, password))
                else:
                    print(f"跳过（缺 email 或 password）: {line}")
        else:
            # 单条：email password  或  email----password
            if len(extra) >= 2:
                records.append((extra[0], extra[1]))
            elif len(extra) == 1:
                email, password = _parse_record(extra[0])
                if email and password:
                    records.append((email, password))

    if not records:
        print("add 需要 email 和 password（或用 --random N 随机生成）。")
        print("例：python main.py email add user@domain.com Password123")
        print("    python main.py email add --random 10 --domain domain.com --out new.txt")
        exit(1)

    ok = fail = 0
    created = []   # 成功创建的 (email, password)，用于存档
    for email, password in records:
        local, domain = split_email(email, resolve_domain())
        if not domain:
            print(f"[失败] {email}: 未指定域名（用 user@domain 或 --domain）")
            fail += 1
            continue
        try:
            create_email_account(domain, local, password, quota=quota, limit=limit)
            print(f"[新增] {local}@{domain}----{password}  quota={quota}MB limit={limit}")
            created.append((f"{local}@{domain}", password))
            ok += 1
        except MXRouteError as e:
            print(f"[失败] {local}@{domain}: [{e.status} {e.code}] {e}")
            fail += 1

    # 存档成功创建的凭据（随机模式默认存，避免密码丢失），
    # 并在末尾追加一段：所有邮箱地址用逗号拼成一行
    if created and out_opt:
        emails_csv = ",".join(em for em, _ in created)
        with open(out_opt, "a", encoding="utf-8") as f:
            for em, pw in created:
                f.write(f"{em}----{pw}\n")
            f.write("---- emails ----\n")
            f.write(emails_csv + "\n")
        print(f"已追加 {len(created)} 条凭据到 {out_opt}")
        print(f"邮箱逗号列表：{emails_csv}")
    elif created:
        emails_csv = ",".join(em for em, _ in created)
        print(f"邮箱逗号列表：{emails_csv}")
        if random_opt is not None:
            print("提示：随机生成的密码仅此一次可见，建议加 --out new.txt 存档")

    print(f"---- 新增完成：成功 {ok} / 失败 {fail} ----")


async def _run_del(extra, resolve_domain):
    target = extra[0] if extra else ""
    is_file = bool(target) and os.path.isfile(target)

    emails = []
    if is_file:
        for line in _load_lines(target, True):
            email, _ = _parse_record(line)
            if email:
                emails.append(email)
    else:
        emails = [x for x in extra if not x.startswith("--")]

    if not emails:
        print("del 需要 email。例：python main.py email del user@domain.com")
        exit(1)

    ok = fail = 0
    for email in emails:
        local, domain = split_email(email, resolve_domain())
        if not domain:
            print(f"[失败] {email}: 未指定域名（用 user@domain 或 --domain）")
            fail += 1
            continue
        try:
            delete_email_account(domain, local)
            print(f"[删除] {local}@{domain}")
            ok += 1
        except MXRouteError as e:
            print(f"[失败] {local}@{domain}: [{e.status} {e.code}] {e}")
            fail += 1
    print(f"---- 删除完成：成功 {ok} / 失败 {fail} ----")


async def _run_list(extra, resolve_domain):
    explicit = ""
    if extra and not extra[0].startswith("--"):
        explicit = extra[0]
    domain = resolve_domain(explicit)
    if not domain:
        print("list 需要域名。例：python main.py email list domain.com（或配置 MXROUTE_DEFAULT_DOMAIN）")
        exit(1)
    accounts = list_email_accounts(domain)
    if not accounts:
        print(f"{domain} 下没有邮箱账号。")
        return
    print(f"{domain} 共 {len(accounts)} 个邮箱账号：")
    for a in accounts:
        email = a.get("email") or f"{a.get('username', '')}@{domain}"
        quota = a.get("quota", "?")
        usage = a.get("usage", "?")
        suspended = a.get("suspended")
        flag = " [已停用]" if suspended else ""
        print(f"  {email}\tquota={quota}MB usage={usage}MB{flag}")


# ==== inbox 子命令：IMAP 登录邮箱读信、抓 claude.ai / anthropic.com 登录链接 ====

def _is_host_port_line(line: str):
    """检测 host:port 格式（无 @ 且端口为数字），返回 (host, port) 或 None"""
    if "@" in line:
        return None
    if ":" in line:
        host, _, port_str = line.rpartition(":")
        if host.strip() and port_str.strip().isdigit():
            return host.strip(), int(port_str.strip())
    return None


def _parse_inbox_record(line: str) -> tuple:
    """解析 inbox 凭据行，额外支持 email:password 格式（: 分隔）"""
    for sep in ("----", "|", "\t"):
        if sep in line:
            parts = [p.strip() for p in line.split(sep) if p.strip()]
            email = parts[0] if parts else ""
            password = parts[1] if len(parts) > 1 else ""
            return email, password
    if "@" in line and ":" in line:
        at_pos = line.index("@")
        colon_pos = line.index(":", at_pos)
        email = line[:colon_pos].strip()
        password = line[colon_pos + 1:].strip()
        if email and password:
            return email, password
    parts = line.split()
    email = parts[0] if parts else ""
    password = parts[1] if len(parts) > 1 else ""
    return email, password


def _decode_mime_header(raw: str) -> str:
    parts = []
    for fragment, charset in _decode_header(raw or ""):
        if isinstance(fragment, bytes):
            parts.append(fragment.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(fragment)
    return "".join(parts)


def _extract_body(msg) -> str:
    if msg.is_multipart():
        html = text = ""
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


_B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _decode_proofpoint(url: str) -> str:
    """还原 Proofpoint URL Defense 重写后的链接。

    v3 形态：https://urldefense.com/v3/__<真实URL>__;<b64替换表>!!<签名>$
    也兼容邮件里出现的畸形形态：真实域名后直接跟 *…__;<b64>!!…$
    （网关把 # / ? 等特殊字符换成 *，用 __; 后的 base64 记录被替换的原字符）。
    v2 形态：https://urldefense.proofpoint.com/v2/url?u=<编码URL>&d=…
    非 Proofpoint 链接原样返回。
    """
    if not url:
        return url
    # ---- v3 ----
    m = re.search(r"(.+?)__;([A-Za-z0-9\-_=]*)!!", url)
    if m and "__;" in url:
        inner = re.sub(r"^https?://urldefense\.com/v3/__", "", m.group(1))
        enc = m.group(2)
        try:
            repl = base64.urlsafe_b64decode(enc + "=" * (-len(enc) % 4)).decode("utf-8", "replace")
        except Exception:
            repl = ""
        out, i, ri = [], 0, 0
        while i < len(inner):
            if inner[i] == "*":
                if i + 1 < len(inner) and inner[i + 1] == "*":
                    run = _B64_ALPHABET.find(inner[i + 2]) if i + 2 < len(inner) else -1
                    run = run if run > 0 else 1
                    out.append(repl[ri:ri + run]); ri += run; i += 3
                else:
                    out.append(repl[ri:ri + 1]); ri += 1; i += 1
            else:
                out.append(inner[i]); i += 1
        return "".join(out)
    # ---- v2 ----
    m2 = re.search(r"urldefense\.(?:proofpoint\.)?com/v2/url\?u=([^&\s\"'<>]+)", url)
    if m2:
        from urllib.parse import unquote
        return unquote(m2.group(1).replace("-", "%").replace("_", "/"))
    return url


def _extract_claude_link(body: str) -> str:
    # 折叠 quoted-printable 软换行：有些 bot 发信把邮件标成 7bit/8bit 却按 QP 折行，
    # get_payload(decode=True) 不会去掉行尾的 "=\r\n"，导致长链接被截断在 "...=" 处。
    # 按 QP 规范行尾裸露的 = 必为软换行（真正的 = 会编码成 =3D），折叠是安全的。
    body = re.sub(r"=\r?\n", "", body or "")
    url_re = re.compile(
        r"https://(?:[a-zA-Z0-9_-]+\.)*(?:claude\.ai|claude\.com|anthropic\.com|openai\.com|chatgpt\.com|urldefense\.(?:proofpoint\.)?com)/[^\s\"'<>]+",
        re.IGNORECASE,
    )
    target_re = re.compile(
        r"https://(?:[a-zA-Z0-9_-]+\.)*(?:claude\.ai|claude\.com|anthropic\.com|openai\.com|chatgpt\.com)/",
        re.IGNORECASE,
    )
    static_re = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|otf|ttf|woff2?|eot)(\?|#|$)", re.IGNORECASE)
    assets_re = re.compile(r"^https://assets\.", re.IGNORECASE)
    tracker_re = re.compile(r"^https://[^/]*(?:mail\.anthropic\.com|(?:email|mail|url\d*|t|links?|click)\.openai\.com)/", re.IGNORECASE)
    login_kw = re.compile(r"(sign[-_]?in|magic|verify|auth|login|token|invite|onboard)", re.IGNORECASE)
    candidates = []
    for u in url_re.findall(body or ""):
        # HTML 正文里的链接带实体编码（&amp; / &#61; / &#x2F; 等），先还原再解析，
        # 否则抓到的登录链接会含 &amp; 之类字符导致打开失败。
        u = html_pkg.unescape(u)
        u = _decode_proofpoint(u)
        if not target_re.match(u):
            continue
        if static_re.search(u) or assets_re.match(u) or tracker_re.match(u):
            continue
        if u not in candidates:
            candidates.append(u)
    if not candidates:
        return ""
    preferred = [u for u in candidates if login_kw.search(u)]
    return preferred[0] if preferred else candidates[0]


def _imap_connect(host: str, port: int, timeout: int = 30):
    """尝试 SSL 连接；若失败（如服务器仅支持 STARTTLS）则回退到 143+STARTTLS。"""
    import ssl
    try:
        return imaplib.IMAP4_SSL(host, port, timeout=timeout)
    except (ssl.SSLError, OSError):
        starttls_port = 143
        print(f"  SSL 连接失败，尝试 STARTTLS ({host}:{starttls_port}) ...")
        imap = imaplib.IMAP4(host, starttls_port, timeout=timeout)
        imap.starttls()
        return imap


def _imap_read_one(email_addr: str, password: str, host: str, port: int = 993,
                   count: int = 1, search: str = "ALL", delete: bool = False) -> None:
    """登录一个邮箱，打印最近 count 封邮件并尝试抓 claude 链接。
    delete=True 时删除抓到链接的邮件（没抓到链接的不动）。"""
    print(f"\n== {email_addr} @ {host}:{port} ==")
    imap = None
    try:
        imap = _imap_connect(host, port)
        imap.login(email_addr, password)
        imap.select("INBOX")
        # 用 UID 而非序号：删除后序号会变，UID 不会
        typ, data = imap.uid("search", None, search)
        ids = data[0].split() if data and data[0] else []
        if not ids:
            print("  收件箱为空（或无匹配邮件）。")
            return
        for uid in ids[-count:][::-1]:
            typ, msg_data = imap.uid("fetch", uid, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                continue
            msg = email_pkg.message_from_bytes(msg_data[0][1])
            subject = _decode_mime_header(msg.get("Subject", "(无主题)"))
            from_addr = _decode_mime_header(msg.get("From", ""))
            date = msg.get("Date", "")
            print(f"  日期: {date}")
            print(f"  发件人: {from_addr}")
            print(f"  主题: {subject}")
            link = _extract_claude_link(_extract_body(msg))
            if link:
                print(f"  登录链接: {link}")
                if delete and imap_delete_uid(imap, uid):
                    print("  已删除该邮件")
            print()
    except imaplib.IMAP4.error as e:
        print(f"  [登录/读取失败] {e}")
    except Exception as e:
        print(f"  [连接异常] {e}")
    finally:
        if imap:
            try:
                imap.logout()
            except Exception:
                pass


async def _run_inbox(extra):
    """python main.py email inbox 'user@domain----password' [--count N] [--search 'FROM anthropic']
       也支持文件批量：每行 email----password
       也支持 host:port + email:password 格式（自动识别 host 行）"""
    count_opt = _pop_opt(extra, "--count")
    search_opt = _pop_opt(extra, "--search")
    host_opt = _pop_opt(extra, "--host")
    delete = "--keep" not in extra
    extra = [a for a in extra if a != "--keep"]
    count = int(count_opt) if count_opt is not None else 1
    search = search_opt or "ALL"
    auto_host = ""
    auto_port = 993

    target = extra[0] if extra else ""
    is_file = bool(target) and os.path.isfile(target)

    accounts = []
    if is_file:
        for line in _load_lines(target, True):
            hp = _is_host_port_line(line)
            if hp:
                if not auto_host:
                    auto_host, auto_port = hp
                continue
            email_addr, password = _parse_inbox_record(line)
            if email_addr and password:
                accounts.append((email_addr, password))
    elif extra:
        lines = []
        for arg in extra:
            for ln in arg.splitlines():
                s = ln.strip()
                if s and not s.startswith("#"):
                    lines.append(s)
        for line in lines:
            hp = _is_host_port_line(line)
            if hp:
                if not auto_host:
                    auto_host, auto_port = hp
                continue
            email_addr, password = _parse_inbox_record(line)
            if email_addr and password:
                accounts.append((email_addr, password))
        if not accounts and len(extra) >= 2:
            accounts.append((extra[0].strip(), extra[1].strip()))

    host = host_opt or auto_host or MXROUTE_SERVER
    port = auto_port
    if not host:
        print("未配置邮件服务器：设置 config.MXROUTE_SERVER 或加 --host，或在输入中包含 host:port 行")
        exit(1)

    if not accounts:
        print("inbox 需要 email 和 password。例：")
        print("  python main.py email inbox 'user@domain.com:Password123'")
        print("  python main.py email inbox 'user@domain.com----Password123'")
        print("  python main.py email inbox accounts.txt --count 3 --search 'FROM anthropic'")
        print("  支持 host:port 行自动识别 IMAP 服务器")
        exit(1)

    for email_addr, password in accounts:
        _imap_read_one(email_addr, password, host, port=port, count=count, search=search,
                       delete=delete)
