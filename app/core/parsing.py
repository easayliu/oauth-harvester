"""输入解析：账号行、session、cookie jar、subus/aws 凭证等多种格式（由 main.py 拆分而来）"""

import json
import logging
import os
import re

logger = logging.getLogger(__name__)


def split_input(raw: str) -> list[str]:
    """智能分割输入。支持：
      - `----` 分隔（email----password----totp）
      - TAB 分隔
      - `|` 分隔（email|password|recovery_email|totp|year|country）
      - 任意空白（含多个空格、TAB 混合），兼容 Excel/WPS 复制粘贴出的松散格式
    """
    raw = raw.strip()
    if "----" in raw:
        return raw.split("----")
    # 先试纯 TAB；若只切出 1 段但内部含空白，再按任意空白 re.split
    if "\t" in raw:
        return raw.split("\t")
    if "|" in raw:
        return raw.split("|")
    # 按一个或多个空白（含 TAB）分割
    return re.split(r"\s+", raw)


_LOOSE_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TOTP_TAIL_RE = re.compile(r"([A-Za-z2-7]{32})\s*$")


def _parse_loose_totp_line(raw: str):
    """锚点解析：email 在行首 + 32 位 base32 totp 在行尾，中间剩下当 password。
    用于分隔符长度不一致（如 ----、-----、------、--）的脏行。
    匹配不到返回 None，由上层走标准 split 流程或抛错。
    """
    s = raw.strip()
    em = _LOOSE_EMAIL_RE.match(s)
    if not em:
        return None
    tm = _TOTP_TAIL_RE.search(s)
    if not tm or tm.start() <= em.end():
        return None
    middle = s[em.end():tm.start()].strip(" \t-")
    if not middle:
        return None
    return em.group(0), middle, tm.group(1)


def _segments_clean(parts: list[str]) -> bool:
    """所有段都不以 `-` 开头/结尾，视为标准 `----` 切分结果。"""
    return all(not p.startswith("-") and not p.endswith("-") for p in (s.strip() for s in parts))


def parse_input(raw: str) -> tuple[str, str, str]:
    """解析输入参数，支持多种格式:
      - email----password----totp_secret                            (3段)
      - email----password----忽略----totp_secret                    (4段)
      - email----password----recovery_email----totp_secret----year----country  (6段)
      - email<任意 2+ 个连字符>password<任意 2+ 个连字符>totp_secret  (锚点解析，totp 必须是 32 位 base32 在行尾)
    额外容错:
      - 行首数字序号 (如 "20 user@x.com|pwd|totp ...") 会被剥掉
      - 行尾 JSON (如 '... totp {"refreshToken": "..."}') 会被剥掉
    """
    raw = raw.strip()
    brace = raw.find("{")
    if brace != -1:
        raw = raw[:brace].rstrip()
    m = re.match(r"^\d+\s+(?=\S+@)", raw)
    if m:
        raw = raw[m.end():]
    parts = split_input(raw)
    if len(parts) in (3, 4, 6) and _segments_clean(parts):
        email = parts[0]
        password = parts[1]
        totp_secret = parts[2] if len(parts) == 3 else parts[3]
        return email, password, totp_secret

    loose = _parse_loose_totp_line(raw)
    if loose is not None:
        return loose

    raise ValueError("参数格式错误，应为: email----password----totp_secret (3段) 或 email----password----忽略----totp_secret (4段/6段)")


def parse_account_input(raw: str) -> tuple[str, str]:
    """解析账号输入，提取 email 和 password（兼容多种格式）"""
    parts = [p.strip() for p in split_input(raw)]
    if len(parts) < 2:
        raise ValueError("参数格式错误，至少需要 email----password")
    return parts[0], parts[1]


def parse_session_input(raw: str) -> tuple[str, str, str]:
    """解析 session 模式输入，自动定位 sessionKey 字段（sk-ant- 开头）
    支持格式:
      - email----password----sessionKey
      - email----password----时间----sessionKey----uuid
      - email<Tab/空格>sk-ant-xxx       （仅 email + key，password 留空）
      - 单独一行 sk-ant-xxx              （email/password 留空）
      - 或用 Tab 分隔
    """
    raw = raw.strip()
    # 用正则直接提取 sk-ant key，最稳健
    m = re.search(r"sk-ant-(?:(?!----)\S)+", raw)
    if not m:
        raise ValueError("未找到 sk-ant- 开头的 sessionKey 字段")
    session_key = m.group(0)

    # 去掉 session_key 后再切分剩余部分，提取 email / password
    remainder = (raw[: m.start()] + raw[m.end():]).strip()
    # 优先按 ---- 切，否则按任意空白切
    if "----" in remainder:
        parts = [p.strip() for p in remainder.split("----") if p.strip()]
    else:
        parts = [p for p in re.split(r"\s+", remainder) if p]

    email = parts[0] if len(parts) >= 1 else ""
    password = parts[1] if len(parts) >= 2 else ""
    return email, password, session_key


# 浏览器扩展导出 cookie 时 sameSite 取值 → Playwright 接受的取值
_PW_SAMESITE = {
    "no_restriction": "None",
    "none": "None",
    "lax": "Lax",
    "strict": "Strict",
    "unspecified": "Lax",
    "": "Lax",
}


def _normalize_cookies_for_playwright(raw_cookies: list, domain_filter: str = "claude.ai") -> list:
    """把浏览器扩展导出的 cookie 数组（.crash/.json）转成 Playwright add_cookies 接受的格式。
    - sameSite: unspecified/no_restriction → Lax/None
    - expirationDate/expiration → expires(int 秒)；session cookie → -1
    - 丢弃 hostOnly/storeId/id 等 Playwright 不认的字段
    - 仅保留 domain 含 domain_filter 的 cookie（默认 claude.ai）
    """
    result = []
    for c in raw_cookies:
        if not isinstance(c, dict):
            continue
        name = c.get("name")
        if not name:
            continue
        domain = c.get("domain", "")
        if domain_filter and domain_filter not in domain:
            continue
        cookie = {
            "name": name,
            "value": c.get("value", ""),
            "domain": domain or f".{domain_filter}",
            "path": c.get("path", "/") or "/",
            "httpOnly": bool(c.get("httpOnly", False)),
            "secure": bool(c.get("secure", False)),
            "sameSite": _PW_SAMESITE.get(str(c.get("sameSite", "")).lower(), "Lax"),
        }
        if c.get("session"):
            cookie["expires"] = -1
        else:
            exp = c.get("expirationDate", c.get("expiration"))
            try:
                cookie["expires"] = int(float(exp)) if exp is not None else -1
            except (TypeError, ValueError):
                cookie["expires"] = -1
        result.append(cookie)
    return result


def parse_cookie_jar(raw: str, is_file: bool = True) -> tuple[str, list]:
    """解析浏览器 cookie 导出（.crash/.json，内容为 cookie 对象数组，或 {"cookies": [...]}）。
    返回 (sessionKey, 规范化后的 claude.ai cookies)。未找到 sessionKey 时抛 ValueError。
    """
    if is_file:
        with open(raw, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = json.loads(raw)
    if isinstance(data, dict):
        data = data.get("cookies", [])
    if not isinstance(data, list):
        raise ValueError("不是 cookie 数组格式")
    session_key = ""
    for c in data:
        if isinstance(c, dict) and c.get("name") == "sessionKey":
            session_key = (c.get("value") or "").strip()
            break
    if not session_key:
        raise ValueError("cookie 数组中未找到 sessionKey")
    return session_key, _normalize_cookies_for_playwright(data)


def looks_like_cookie_jar(path: str) -> bool:
    """判断文件是否是浏览器 cookie 导出 JSON（用于 session/batch 自动识别 .crash/.json）。"""
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return False
    if isinstance(data, dict):
        data = data.get("cookies", [])
    return isinstance(data, list) and any(
        isinstance(c, dict) and "name" in c and "value" in c for c in data
    )


def collect_cookie_jars(path: str) -> list[tuple]:
    """从文件或目录收集 cookie 导出，返回 [(label, session_key, cookies), ...]。
    目录会扫描其中所有 .crash/.json 文件。"""
    if os.path.isdir(path):
        files = [
            os.path.join(path, n)
            for n in sorted(os.listdir(path))
            if n.lower().endswith((".crash", ".json"))
        ]
    else:
        files = [path]

    jars = []
    for fp in files:
        if not looks_like_cookie_jar(fp):
            logger.warning(f"跳过非 cookie 文件: {fp}")
            continue
        try:
            session_key, cookies = parse_cookie_jar(fp)
        except (ValueError, OSError, json.JSONDecodeError) as e:
            logger.warning(f"解析失败 {fp}: {e}")
            continue
        jars.append((os.path.basename(fp), session_key, cookies))
    return jars


def _sessionkey_from_jar(jar) -> str:
    """从单个 cookie jar（cookie 字典数组，或 {"cookies":[...]}）里取 name==sessionKey 的 value。"""
    if isinstance(jar, dict):
        jar = jar.get("cookies", [])
    if not isinstance(jar, list):
        return ""
    for c in jar:
        if isinstance(c, dict) and c.get("name") == "sessionKey":
            return (c.get("value") or "").strip()
    return ""


def _is_cookie_list(data) -> bool:
    """判断一个 list 是否是「单个 jar」（元素为 cookie 字典），而非「jar 的数组」。"""
    return isinstance(data, list) and any(
        isinstance(c, dict) and "name" in c and "value" in c for c in data
    )


def extract_sessionkeys_from_text(text: str) -> list[str]:
    """从一段文本里提取一个或多个 cookie jar 的 sessionKey，支持：
      - 单个 cookie 数组            [{...}]
      - jar 的数组（多账号）        [[{...}], [{...}]]
      - 每行一个 cookie 数组(JSONL) [{...}]\n[{...}]
      - 顶层 {"cookies":[...]} 或其数组
    返回 sessionKey 列表（已去重保序，跳过没有 sessionKey 的 jar）。
    """
    text = (text or "").strip()
    jars = []
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None

    if parsed is not None:
        if isinstance(parsed, dict):
            jars = [parsed]
        elif isinstance(parsed, list):
            jars = [parsed] if _is_cookie_list(parsed) else parsed
    else:
        # 整体不是合法 JSON：按 JSONL 处理，每行单独 parse 一个 jar
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                jars.append(json.loads(line))
            except ValueError:
                continue

    keys, seen = [], set()
    for jar in jars:
        sk = _sessionkey_from_jar(jar)
        if sk and sk not in seen:
            seen.add(sk)
            keys.append(sk)
    return keys


def parse_subus_input(raw: str) -> tuple[str, str, str]:
    """解析 subus 推送输入。格式: email----api_key----workspace_id"""
    parts = [p.strip() for p in split_input(raw)]
    if len(parts) < 3:
        raise ValueError("subus 参数格式: email----api_key----workspace_id（至少 3 段）")
    return parts[0], parts[1], parts[2]


_AWS_AK_RE = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
_AWS_REGION_CODE_RE = re.compile(r"^[a-z]{2}-[a-z]+-\d+$")

# AWS 控制台里区域常显示为城市名；输入里若写地名（如 Stockholm）按此表换成 region code。
_AWS_REGION_BY_CITY = {
    "n. virginia": "us-east-1", "virginia": "us-east-1",
    "ohio": "us-east-2",
    "n. california": "us-west-1", "california": "us-west-1",
    "oregon": "us-west-2",
    "cape town": "af-south-1",
    "hong kong": "ap-east-1",
    "mumbai": "ap-south-1",
    "hyderabad": "ap-south-2",
    "tokyo": "ap-northeast-1",
    "seoul": "ap-northeast-2",
    "osaka": "ap-northeast-3",
    "singapore": "ap-southeast-1",
    "sydney": "ap-southeast-2",
    "jakarta": "ap-southeast-3",
    "melbourne": "ap-southeast-4",
    "canada": "ca-central-1", "central": "ca-central-1", "montreal": "ca-central-1",
    "frankfurt": "eu-central-1",
    "zurich": "eu-central-2",
    "ireland": "eu-west-1",
    "london": "eu-west-2",
    "paris": "eu-west-3",
    "stockholm": "eu-north-1",
    "milan": "eu-south-1",
    "spain": "eu-south-2",
    "bahrain": "me-south-1",
    "uae": "me-central-1",
    "sao paulo": "sa-east-1", "são paulo": "sa-east-1",
    "tel aviv": "il-central-1",
}


def resolve_aws_region(name: str) -> str:
    """把区域字段归一成 region code：已是 region code 原样返回；地名（Stockholm）查表；
    都不匹配则原样返回（交给上层/AWS 报错），空串返回空串。
    """
    s = (name or "").strip()
    if not s or _AWS_REGION_CODE_RE.match(s):
        return s
    return _AWS_REGION_BY_CITY.get(s.lower(), s)


# 标注格式（多行，每行 `字段: 值`）。把同义的中英文标签归一到内部字段名。
_AWS_LABEL_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9 ._/()-]*?)\s*[:：]\s*(.*)$")
_AWS_LABEL_ALIASES = {
    "email": "email", "account": "email", "邮箱": "email", "账号": "email",
    "2fa": "totp", "2fa secret": "totp", "totp": "totp", "mfa": "totp", "otp": "totp",
    "access key": "akid", "access key id": "akid", "accesskey": "akid",
    "access key id (akid)": "akid", "akid": "akid",
    "secret access key": "sak", "secret key": "sak", "secretkey": "sak",
    "secret access key (sak)": "sak", "sak": "sak",
    "password": "password", "pwd": "password", "pass": "password", "密码": "password",
    "region": "region", "区域": "region",
    "ip": "ip", "limit": "limit",  # 解析但不使用（IP 是代理国别，非 AWS 区域）
}


def _aws_label_field(line: str):
    """若 line 是已知标注字段行（如 `2FA: xxx`），返回其归一字段名；否则 None。"""
    m = _AWS_LABEL_RE.match(line)
    if not m:
        return None
    key = re.sub(r"\s+", " ", m.group(1).strip().lower())
    return _AWS_LABEL_ALIASES.get(key)


def _split_email_password(val: str) -> tuple[str, str]:
    """从 `email:password` / `email password` / 纯 email 中拆出 (email, password)。
    密码可能含特殊符号，但 email 形态固定，故先锚定 email 再取其后剩余部分当密码。
    """
    val = (val or "").strip()
    m = _LOOSE_EMAIL_RE.match(val)
    if not m:
        return val, ""
    email = m.group(0)
    rest = val[m.end():].lstrip(" \t:：|/")
    return email, rest.strip()


def _parse_aws_labeled(raw: str):
    """解析标注格式（多行 `字段: 值`），匹配不到 email 标签返回 None：

        Email: user@x.com:password      # email:password 合写
        2FA: <base32 totp>
        Access key: AKIA...
        Secret access key: <sak,可含 / >
        IP: Macedonia                    # 代理国别，忽略（不当 region）
        Limit: 5 (AI 10 RPM)             # 忽略

    返回 (email, password, totp, akid, sak, region)。同一字段重复出现取首次。
    """
    fields: dict[str, str] = {}
    for line in raw.splitlines():
        m = _AWS_LABEL_RE.match(line.strip())
        if not m:
            continue
        canon = _AWS_LABEL_ALIASES.get(re.sub(r"\s+", " ", m.group(1).strip().lower()))
        if canon:
            fields.setdefault(canon, m.group(2).strip())
    if "email" not in fields:
        return None
    email, pwd_from_email = _split_email_password(fields["email"])
    password = fields.get("password") or pwd_from_email
    region = resolve_aws_region(fields["region"]) if fields.get("region") else ""
    return (email, password, fields.get("totp", ""),
            fields.get("akid", ""), fields.get("sak", ""), region)


def split_aws_records(text: str) -> list[str]:
    """把 AWS 输入文本拆成账号记录列表，兼容两种排布：
      - 传统格式：每行一条记录（空行、`#` 注释行跳过）。
      - 标注格式：连续的 `字段: 值` 标签行归为一条多行记录；遇到空行 / `#` 注释 /
        非标签行 / 下一个 `Email:` 标签即结束当前记录。
    """
    records: list[str] = []
    block: list[str] = []

    def flush():
        if block:
            records.append("\n".join(block))
            block.clear()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        # 空行 / `#` 注释 / CLI flag（`--kiro` 等误混进记录流的行）都跳过：
        # 账号记录永远不以 `--` 开头，故安全，避免 flag 被当成账号解析失败。
        if not line or line.startswith("#") or line.startswith("--"):
            flush()
            continue
        field = _aws_label_field(line)
        if field is not None:
            if field == "email" and block:  # 新 Email 标签开启新记录
                flush()
            block.append(line)
        else:  # 非标签行 → 传统单行记录
            flush()
            records.append(line)
    flush()
    return records


def read_aws_records(raw_input: str, is_file: bool) -> list[str]:
    """读取 AWS 输入（文件或单条字符串），返回账号记录列表。见 split_aws_records。"""
    text = open(raw_input, "r").read() if is_file else (raw_input or "")
    return split_aws_records(text)


def parse_aws_input(raw: str) -> tuple[str, str, str, str, str, str]:
    """解析 aws 模式输入，返回 (email, password, totp, akid, sak, region)。
    region 仅在格式 C 出现，其余格式为空串。自动识别三种格式：

    格式 A（带密码/TOTP，可选 AK/SK，`----` 分隔）:
        email----password----totp_secret[----access_key_id[----secret_access_key]]
      - 5 段: 全字段；4 段: 缺 secret_access_key；3 段: AK/SK 留空。

    格式 B（纯 AK/SK 联邦登录，无密码/TOTP）:
        access_key_id<sep>secret_access_key[<sep>email]
      检测条件：第 1 段匹配 AKIA/ASIA + 16 位大写字母数字。返回 password/totp 为空。
      email 可省略（如空格分隔的 `AKID SAK`，用于 aws-diag/aws-quota 只需 AK/SK 的场景）。

    格式 B2（email 在前的纯 AK/SK 联邦登录，无密码/TOTP）:
        email<sep>access_key_id<sep>secret_access_key
      检测条件：第 1 段是邮箱 + 第 2 段匹配 AKIA/ASIA。返回 password/totp 为空。

    格式 C（` / ` 分隔，AK/SK 在 totp 之前，可带 region/tag）:
        email / password / access_key_id / secret_access_key / totp / region / tag
      - 分隔符是「两侧带空白的斜杠」，因此 AWS SAK 内部的裸 `/`（base64）不会被切断。
      - 检测条件：首段是邮箱 + 第 3 段是 AKIA/ASIA。region 接受 region code 或城市名，
        末尾 tag（如国别标记）解析但不使用。

    格式 D（标注格式，多行 `字段: 值`，见 _parse_aws_labeled）:
        Email: user@x.com:password / 2FA / Access key / Secret access key / IP / Limit
      检测条件：含 `Email:`（或 `账号:` 等同义）标签行。email:password 合写会被拆开。
    """
    raw = raw.strip()

    # 格式 D：标注格式（含 `Email:` 标签行），email/password 可能合写在 Email 行
    if re.search(r"(?im)^\s*(email|account|邮箱|账号)\s*[:：]", raw):
        labeled = _parse_aws_labeled(raw)
        if labeled is not None:
            return labeled

    # 格式 C：按「两侧带空白的斜杠」切分，避免误切 SAK 里的裸 `/`
    slash_parts = [p.strip() for p in re.split(r"\s+/\s+", raw)]
    if (len(slash_parts) >= 4
            and _LOOSE_EMAIL_RE.fullmatch(slash_parts[0])
            and _AWS_AK_RE.match(slash_parts[2])):
        email = slash_parts[0]
        password = slash_parts[1]
        access_key_id = slash_parts[2]
        secret_access_key = slash_parts[3]
        totp_secret = slash_parts[4] if len(slash_parts) >= 5 else ""
        region = resolve_aws_region(slash_parts[5]) if len(slash_parts) >= 6 else ""
        return email, password, totp_secret, access_key_id, secret_access_key, region

    parts = [p.strip() for p in split_input(raw)]
    if not parts:
        raise ValueError("aws 参数为空")

    if _AWS_AK_RE.match(parts[0]):
        # 格式 B：access_key_id<sep>secret_access_key[<sep>email]
        #   - 2 段：纯 AK/SK（无 email，如 aws-diag/aws-quota 用空格分隔的 `AKID SAK`）；
        #   - 3 段：带 email 的联邦登录。
        if len(parts) < 2:
            raise ValueError("AK/SK 格式至少需要 access_key_id<sep>secret_access_key")
        access_key_id = parts[0]
        secret_access_key = parts[1]
        email = parts[2] if len(parts) >= 3 else ""
        return email, "", "", access_key_id, secret_access_key, ""

    # 格式 B2：email AKID SAK（联邦登录）。第 2 段是 AK 即可判定，
    # 不会与格式 A 冲突（密码不可能恰好是 AKIA/ASIA + 16 位大写字母数字）
    if (len(parts) >= 3
            and _LOOSE_EMAIL_RE.fullmatch(parts[0])
            and _AWS_AK_RE.match(parts[1])):
        return parts[0], "", "", parts[1], parts[2], ""

    if len(parts) < 3:
        raise ValueError("aws 参数至少需要 email----password----totp_secret")
    email = parts[0]
    password = parts[1]
    totp_secret = parts[2]
    access_key_id = parts[3] if len(parts) >= 4 else ""
    secret_access_key = parts[4] if len(parts) >= 5 else ""
    return email, password, totp_secret, access_key_id, secret_access_key, ""


