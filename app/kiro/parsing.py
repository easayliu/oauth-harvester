"""Kiro：输入解析（账号块、refresh token、IDC 凭证）与 kiro.json 读写（由 main.py 拆分而来）"""

from datetime import datetime, timedelta
import json
import logging
import os
import re
import uuid

from app.settings import KIRO_IDC_NEW_PASSWORD
from app.core.parsing import _TOTP_TAIL_RE, _parse_loose_totp_line, split_input
from app.kiro.api import KIRO_OUTPUT_FILE, _idc_region_from_start_url

logger = logging.getLogger(__name__)


_IDC_LABEL_PATTERNS = {
    "default_url": (
        r"^\s*(?:默认\s*)?AWS\s*access\s*portal\s*URL\s*(?:[（(][^）)]*[)）])?\s*[:：]\s*(\S+)",
        r"^\s*默认\s*[^:：]*[:：]\s*(https?://\S+)",
    ),
    "dual_url": (
        r"^\s*双栈\s*AWS\s*access\s*portal\s*URL\s*[:：]\s*(\S+)",
        r"^\s*dual[\s\-_]*stack[^:：]*[:：]\s*(https?://\S+)",
    ),
    "username": (
        r"^\s*(?:用户名|账号|Username|username|User)\s*[:：]\s*(.+?)\s*$",
    ),
    "temp_password": (
        r"^\s*(?:一次性密码|临时密码|初始密码|One[\s\-]*time\s*password|Temp(?:orary)?\s*password)\s*[:：]\s*(.+?)\s*$",
    ),
    "new_password": (
        r"^\s*(?:新密码|New\s*password)\s*[:：]\s*(.+?)\s*$",
    ),
}


def _try_parse_kiro_idc_labeled(text: str):
    """尝试按"标签:值"多行格式解析一个 IDC 块。
    成功返回 ("idc", start_url, username, temp_pwd, new_pwd)；
    缺关键字段（start_url/username/temp_pwd 之一）时返回 None。
    """
    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for key, patterns in _IDC_LABEL_PATTERNS.items():
            if key in fields:
                continue
            for pat in patterns:
                m = re.match(pat, line, flags=re.IGNORECASE)
                if m:
                    fields[key] = m.group(1).strip()
                    break

    start_url = fields.get("default_url") or fields.get("dual_url")
    username = fields.get("username")
    temp_pwd = fields.get("temp_password")
    new_pwd = fields.get("new_password") or KIRO_IDC_NEW_PASSWORD
    if not (start_url and username and temp_pwd):
        return None
    if not (start_url.startswith("http://") or start_url.startswith("https://")):
        return None
    return ("idc", start_url, username, temp_pwd, new_pwd)


def _split_idc_body(body: str) -> list[str]:
    """按 ---- 切 idc:: 行，正确处理"密码字段首/尾带 `-`"的情况。

    IDC 行结构固定：start_url----username----temp_password[----new_password]。
    password 字段（temp/new）首尾都可能带 `-`，和 4 短横分隔符连起来会变成 `-----`
    （5 个及以上）。普通 split("----") 会把那个 `-` 当成分隔符吃掉，导致密码错一位、
    登录失败。多出来的短横必须补回**密码字段**，而不是干净的 username。

    规则（按分隔符出现顺序定位边界，末 4 个才是真正的分隔符）：
      - 分隔符 #1（username|temp_password 边界）：username 是不含 `-` 的干净账号，
        多出来的短横是 temp_password 的**前导 `-`** → 归下一字段开头。
        例：`bv654490130-----%KLH…` → username=`bv654490130`,
            temp_password=`-%KLH…`（而非把 `-` 甩给 username）。
      - 其它边界（含 temp_password|new_password）：多出来的短横归**前一字段结尾**。
        例：`…h7<-----gJAR…` → temp_password=`…h7<-`, new_password=`gJAR…`。
    `-----`(5) → 补 1 个 `-`；`------`(6) → 补 2 个。
    """
    fields: list[str] = []
    prev_end = 0
    pending_prefix = ""  # 归属"下一字段开头"的短横
    for idx, m in enumerate(re.finditer(r"-{4,}", body)):
        extra = (m.end() - m.start()) - 4  # 超过 4 个的短横
        segment = pending_prefix + body[prev_end:m.start()]
        if idx == 1 and extra > 0:
            # username|temp_password 边界：多出的短横是密码前导，留给下一字段
            fields.append(segment)
            pending_prefix = "-" * extra
        else:
            fields.append(segment + "-" * extra)  # 补回前一字段结尾
            pending_prefix = ""
        prev_end = m.end()
    fields.append(pending_prefix + body[prev_end:])
    return fields


_KIRO_DASH_SEP_RE = re.compile(r"^[—–]{2,}$")
_KIRO_EMAIL_RE = re.compile(r"^[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+$")
_KIRO_TOTP_LIKE_RE = re.compile(r"^[A-Za-z2-7]{16,}$")


def _parse_kiro_multiline_block(stripped: str):
    """解析每行一字段的多行块。布局示例（字段顺序固定，可有索引/空行/分隔/尾部冗余）：
        16
        nguyenthiminh123ak@gmail.com         # email：第一个邮箱形态行
        $Mayy34Kento472                      # password：紧随 email 的下一个非空行
                                             # （可空行占位）
        su4bdov775q7qywzixiuporsmd6lpqo7     # totp：之后第一个 base32 形态行
        2015                                 # 多余字段（年份/国家/字母等）忽略
    或带 recovery email 变体：
        17
        a01128326825@gmail.com
        2fo21KRJMP!@#                        # password 可含 @（如 !@#）
        a011283268255231@hotmail.com         # 跳过 — 非 base32
        plxsujii2uzi4ddoe3iap2o3nzyq42dy
        b
    """
    raw_lines = [ln.strip() for ln in stripped.splitlines()]
    email_idx = next(
        (i for i, v in enumerate(raw_lines) if v and _KIRO_EMAIL_RE.match(v)), -1
    )
    if email_idx < 0:
        return None
    email = raw_lines[email_idx]
    after = raw_lines[email_idx + 1:]
    pw_idx = next((i for i, v in enumerate(after) if v), -1)
    if pw_idx < 0:
        return None
    password = after[pw_idx]
    rest = after[pw_idx + 1:]
    totp = next(
        (v for v in rest if v and _KIRO_TOTP_LIKE_RE.match(v)), None
    )
    if totp is None:
        return None
    return ("builderid", email, password, totp)


def parse_kiro_input(raw: str) -> tuple:
    """解析 kiro 输入，返回 mode-tagged 元组。

    Builder ID（Google）模式 — 旧格式，按"哪一段带 @ 认作 email"定位：
      - email----password----totp
      - email----password----x----totp        （claude 批量格式复用，x 忽略）
      - email<TAB>password<TAB>totp           （kiro-0422.txt 无序号）
      - index<TAB>email<TAB>password<TAB>totp（kiro-0422.txt 带序号）
      - email----password----totp----year----country         （year/country 忽略）
      - email----password----recovery_email----totp----取码链接（missing.txt，
        recovery_email 与尾随取码链接忽略，totp 取第 4 段）
      返回: ("builderid", email, password, totp)

    Builder ID 多行块格式 — 每行一字段，由 ——— 分隔的批量块（kiro/0508-50.txt）：
      [index] / email / password / [recovery_email|空行] / totp / [year/country/...]
      返回: ("builderid", email, password, totp)

    GitHub 模式 — 两种识别方式：
      1) `gh::` 前缀（最稳）：gh::<username>----<password>----<totp>
      2) 启发式：单行 3 段且 field1 不含 `@`，第 3 段为 base32 形态 →
         视作 username----password----totp
      返回: ("github", username, password, totp)

    IDC（IAM Identity Center / AWS Access Portal）模式 — 三种形式：
      1) `idc::` 前缀单行：
         idc::<start_url>----<username>----<temp_password>[----<new_password>]
      2) 标签多行（直接复制平台输出）：
         默认 AWS access portal URL（仅限 IPv4）: https://d-xxxx.awsapps.com/start
         双栈 AWS access portal URL: https://ssoins-xxxx.portal.us-east-1.app.aws
         用户名: t148
         一次性密码: ...
         [新密码: ...]
      `<new_password>` 省略时使用 config.KIRO_IDC_NEW_PASSWORD。
      默认 URL 优先于双栈 URL（更通用）。
      返回: ("idc", start_url, username, temp_pwd, new_pwd)
    """
    stripped = raw.strip()
    if stripped.lower().startswith("gh::"):
        body = stripped[4:]
        parts = [p.strip() for p in split_input(body) if p.strip()]
        if len(parts) != 3:
            raise ValueError(
                f"kiro GitHub 参数格式错误: 期望 gh::username----password----totp，"
                f"got {len(parts)} 段"
            )
        username, password, totp = parts
        return ("github", username, password, totp)

    if stripped.lower().startswith("idc::"):
        body = stripped[5:]
        # 用 _split_idc_body（而非 split_input）：正确保留 temp_password 结尾的 `-`，
        # 只 strip 空白、不 strip 短横，避免把结尾/前导的 `-` 误删。
        parts = [p.strip() for p in _split_idc_body(body) if p.strip()]
        if len(parts) < 3 or len(parts) > 4:
            raise ValueError(
                f"kiro IDC 参数格式错误: 期望 idc::start_url----username"
                f"----temp_password[----new_password]，got {len(parts)} 段"
            )
        start_url = parts[0]
        username = parts[1]
        temp_pwd = parts[2]
        new_pwd = parts[3] if len(parts) == 4 else KIRO_IDC_NEW_PASSWORD
        if not (start_url.startswith("http://") or start_url.startswith("https://")):
            raise ValueError(f"kiro IDC start_url 非法: {start_url}")
        return ("idc", start_url, username, temp_pwd, new_pwd)

    # 多行标签格式（包含 "用户名" 和 "一次性密码"）
    if "\n" in stripped and re.search(r"用户名|Username|User\s*[:：]", stripped, re.I) \
            and re.search(r"一次性密码|临时密码|One[\s\-]*time|Temp", stripped, re.I):
        idc = _try_parse_kiro_idc_labeled(stripped)
        if idc:
            return idc
        raise ValueError("kiro IDC 标签块解析失败: 缺 start_url/username/temp_password 之一")

    # 多行无标签块格式（每行一字段，索引/空行/分隔均允许）
    if "\n" in stripped:
        ml = _parse_kiro_multiline_block(stripped)
        if ml:
            return ml

    parts = [p.strip() for p in split_input(stripped) if p.strip()]
    email_idx = next((i for i, v in enumerate(parts) if "@" in v), -1)
    if email_idx < 0:
        # 启发式 GitHub：3 段，无 @，第 3 段是 base32 形态 TOTP
        if len(parts) == 3 and _KIRO_TOTP_LIKE_RE.match(parts[2]):
            return ("github", parts[0], parts[1], parts[2])
        raise ValueError(f"kiro 参数格式错误: 找不到 email 字段，parts={parts}")

    email = parts[email_idx]
    tail = parts[email_idx + 1:]

    # 脏分隔符（如 ---/-----/------/--）会让 totp 残留前导 `-`，或把 totp 整个吞进 password。
    # 检测信号：tail 任何段有前导/尾随 `-`，或只有 1 段但末尾藏着 32 位 base32。
    if (
        any(t.startswith("-") or t.endswith("-") for t in tail)
        or (len(tail) == 1 and _TOTP_TAIL_RE.search(tail[0]))
    ):
        loose = _parse_loose_totp_line(stripped)
        if loose is not None:
            return ("builderid",) + loose

    if len(tail) == 1:
        # email----password（无 TOTP，账号未开启 2FA）
        password = tail[0]
        totp = ""
    elif len(tail) == 2:
        password, totp = tail
    elif len(tail) == 3:
        password, _, totp = tail
    elif len(tail) == 4:
        password = tail[0]
        # 两种 4 段布局:
        #   a) email----password----totp----year----country          （totp 在 tail[1]）
        #   b) email----password----recovery_email----totp----取码链接（totp 在 tail[2]，
        #      尾随的 GetCodeSMS 链接被忽略）
        if "@" in tail[1]:
            totp = tail[2]
        else:
            totp = tail[1]
    elif len(tail) == 5:
        # email----password----recovery_email----totp----year----country
        password = tail[0]
        totp = tail[2]
    else:
        raise ValueError(
            f"kiro 参数格式错误: email 后应跟 password[+totp+可选忽略段]，got {len(tail)} 段"
        )
    return ("builderid", email, password, totp)


_IDC_PORTAL_URL_HEADER_RE = re.compile(
    r"^\s*(?:默认|双栈|Default|Dual[\s\-]*stack)?\s*AWS\s*access\s*portal\s*URL",
    re.IGNORECASE,
)
_IDC_USERNAME_LINE_RE = re.compile(
    r"^\s*(?:用户名|账号|Username|User)\s*[:：]", re.IGNORECASE
)


def split_kiro_blocks(text: str) -> list[str]:
    """把 kiro 输入文本切成块。
    - 空行 或 `====...` 分隔线 → 块边界
    - 标签块连续堆叠（无空行）时，"AWS access portal URL" 行 + 当前块已含 "用户名"
      → 视作下一块开始
    - 单行（含 `----` 或 TAB）自成一块
    - 多行标签块整体作为一块返回

    特殊：当文本含 `———`（U+2014/U+2013 连续 2+）行时，按其作为唯一分隔符切块，
    块内空行视为字段占位（不切块），整块作为多行字符串交给 parse_kiro_input。
    """
    if any(_KIRO_DASH_SEP_RE.match(ln.strip()) for ln in text.splitlines()):
        blocks_dash: list[list[str]] = []
        cur_dash: list[str] = []
        for raw in text.splitlines():
            line = raw.rstrip("\r\n")
            stripped = line.strip()
            if _KIRO_DASH_SEP_RE.match(stripped) or re.match(r"^=+.*=+$", stripped):
                if cur_dash:
                    blocks_dash.append(cur_dash)
                    cur_dash = []
                continue
            cur_dash.append(line)
        if cur_dash:
            blocks_dash.append(cur_dash)
        out_dash: list[str] = []
        for blk in blocks_dash:
            joined = "\n".join(blk).strip()
            if joined:
                out_dash.append(joined)
        return out_dash

    blocks: list[list[str]] = []
    cur: list[str] = []
    cur_has_username = False
    for raw in text.splitlines():
        line = raw.rstrip("\r\n")
        stripped = line.strip()
        if not stripped or re.match(r"^=+.*=+$", stripped):
            if cur:
                blocks.append(cur)
                cur = []
                cur_has_username = False
            continue
        # 连续堆叠的 IDC 标签块：遇到 portal URL 行且当前块已经收过 用户名 → 切块
        if cur_has_username and _IDC_PORTAL_URL_HEADER_RE.match(line):
            blocks.append(cur)
            cur = []
            cur_has_username = False
        cur.append(line)
        if _IDC_USERNAME_LINE_RE.match(line):
            cur_has_username = True
    if cur:
        blocks.append(cur)

    out: list[str] = []
    for blk in blocks:
        # 单行块
        if len(blk) == 1:
            out.append(blk[0].strip())
            continue
        # 多行：检测是否标签块（用户名+一次性密码）
        joined = "\n".join(blk)
        if re.search(r"用户名|Username|User\s*[:：]", joined, re.I) \
                and re.search(r"一次性密码|临时密码|One[\s\-]*time|Temp", joined, re.I):
            out.append(joined)
        else:
            # 兜底：每行各自当一块（兼容老格式批量文件无空行的情况）
            for ln in blk:
                if ln.strip():
                    out.append(ln.strip())
    return out


def parse_labeled_blocks(text: str) -> tuple[list[tuple[str, str, str]], int]:
    """解析多行块格式，返回 (triples, total_blocks)。块由空行或 '====...' 分隔线切开。

    支持两种块内布局：
      1) 带标签：账号/邮箱:xxx、密码:xxx、2FA密钥/TOTP:xxx（中英文冒号通用）
      2) 无标签按位置：第一个含 @ 的行视为 email，其后按出现顺序，
         非 @ 行依次作为 password、totp，多余的 @ 行（如接收邮箱）忽略。

    凑不齐三元组的块计入 total_blocks 但不进 triples。
    """
    LABEL_KEYS = ("账号", "邮箱", "Email", "email", "密码", "Password",
                  "password", "2FA密钥", "2FA", "TOTP", "totp", "totp_secret")
    label_re = re.compile(
        r"^\s*(?:" + "|".join(re.escape(k) for k in LABEL_KEYS) + r")\s*[:：]"
    )

    def _val(line, *keys):
        for k in keys:
            m = re.match(rf"^\s*{re.escape(k)}\s*[:：]\s*(.+)$", line)
            if m:
                return m.group(1).strip()
        return None

    # 分隔符识别：空行、'==== xxx ===='、或纯由 -/—/–/_/=/─/━ 构成的分隔线
    sep_re = re.compile(r"^(?:=+.*=+|[\-—–_=─━]{2,})$")
    blocks: list[list[str]] = []
    cur: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or sep_re.match(line):
            if cur:
                blocks.append(cur)
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append(cur)

    triples: list[tuple[str, str, str]] = []
    for blk in blocks:
        email = password = totp = None
        for line in blk:
            if email is None:
                v = _val(line, "账号", "邮箱", "Email", "email")
                if v and "@" in v:
                    email = v
                    continue
            if password is None:
                v = _val(line, "密码", "Password", "password")
                if v:
                    password = v
                    continue
            if totp is None:
                v = _val(line, "2FA密钥", "2FA", "TOTP", "totp", "totp_secret")
                if v:
                    totp = v
                    continue
        if not (email and password and totp):
            # 用严格邮箱正则区分 "真邮箱" 与 "含 @ 的密码"（如 'Tiny@26589'、'C!5DFC@%Em.JjK8'）
            email_re = re.compile(
                r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$"
            )
            unlabeled = [l for l in blk if not label_re.match(l)]
            pos_email = next((l for l in unlabeled if email_re.match(l)), None)
            if email is None and pos_email:
                email = pos_email
            if pos_email is not None:
                rest = unlabeled[unlabeled.index(pos_email) + 1:]
            else:
                rest = unlabeled
            # 过滤掉"看起来像邮箱"的行（接收邮箱），但保留含 @ 的密码
            non_email = [l for l in rest if not email_re.match(l)]
            if password is None and len(non_email) >= 1:
                password = non_email[0]
            if totp is None and len(non_email) >= 2:
                totp = non_email[1]
        if email and password and totp:
            triples.append((email, password, totp))
    return triples, len(blocks)


def parse_overage_flag(extra: list) -> "bool | None":
    """从命令行额外参数解析 --overage / --no-overage。
    返回 True=enable，False=disable，None=不处理。--overage 后可跟 enable/disable，默认 enable。
    """
    if "--no-overage" in extra:
        return None
    if "--overage" not in extra:
        return None
    i = extra.index("--overage")
    if i + 1 < len(extra) and not extra[i + 1].startswith("--"):
        val = extra[i + 1].lower()
    else:
        val = "enable"
    if val in ("enable", "on", "true", "1"):
        return True
    if val in ("disable", "off", "false", "0"):
        return False
    raise ValueError(f"--overage 取值无效: {val!r}（支持 enable/disable）")


def parse_idc_batch_flags(extra: list) -> "tuple | None":
    """从命令行额外参数解析共享 IDC 上下文：--idc-url <url> [--region <region>]。

    设置后，kiro 批量文件里的每行只需 `username | password`（或 ---- / TAB / 空白分隔），
    统一按 IDC 登录处理，start_url/region 全文件共享。

    返回 (start_url, region)；未提供 --idc-url 返回 None。
    """
    def _val(flag: str):
        if flag not in extra:
            return None
        i = extra.index(flag)
        if i + 1 < len(extra) and not extra[i + 1].startswith("--"):
            return extra[i + 1]
        raise ValueError(f"{flag} 缺少取值")

    start_url = _val("--idc-url")
    if not start_url:
        return None
    if not (start_url.startswith("http://") or start_url.startswith("https://")):
        raise ValueError(f"--idc-url 非法: {start_url}")
    region = _val("--region") or _idc_region_from_start_url(start_url)
    return (start_url, region)


def parse_idc_credential_line(line: str, start_url: str, region: str) -> tuple:
    """把一行 `username | password` 解析成 IDC 元组（共享 start_url/region）。

    分隔符兼容 split_input（| / ---- / TAB / 空白）。new_password 用默认值。
    返回 ("idc", start_url, username, temp_pwd, new_pwd, region)。
    """
    parts = [p.strip() for p in split_input(line) if p.strip()]
    if len(parts) != 2:
        raise ValueError(f"IDC 行格式错误: 期望 username|password，got {len(parts)} 段")
    username, password = parts
    return ("idc", start_url, username, password, KIRO_IDC_NEW_PASSWORD, region)


def _parse_kiro_text(text: str) -> list:
    """把一段文本解析成 kiro 记录列表。
    兼容四种结构：
      - 裸数组：[ {...}, {...} ]
      - 单条对象：{...}
      - 带外壳的导出：{ "accounts": [ ... ] }
      - JSONL：每行一个 {...}
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # 回退到 JSONL：逐行解析非空行
        records = []
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"JSONL 第 {lineno} 行解析失败: {e}") from None
            if not isinstance(obj, dict):
                raise ValueError(f"JSONL 第 {lineno} 行不是对象")
            records.append(obj)
        if not records:
            raise ValueError("输入既不是合法 JSON 也不含可解析的 JSONL 行")
        return records

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("accounts"), list):
            return data["accounts"]
        return [data]
    raise ValueError(f"无法识别的 kiro 输入: 顶层类型 {type(data).__name__}")


def _load_kiro_records(raw: str, is_file: bool) -> list:
    """从目录、文件或 JSON 字符串读出 kiro 账号记录列表。

    - 目录：扫描其中所有 .json/.txt/.crash 文件（递归子目录），各自解析后合并成一个列表；
            单个文件解析失败只警告并跳过，不影响其它文件。
    - 文件：读出文本后解析。
    - 字符串：直接解析。
    结构兼容见 _parse_kiro_text。
    """
    if os.path.isdir(raw):
        files = []
        for root, _dirs, names in os.walk(raw):
            for n in sorted(names):
                if n.lower().endswith((".json", ".txt", ".crash")):
                    files.append(os.path.join(root, n))
        files.sort()
        if not files:
            raise ValueError(f"目录 {raw} 下没有 .json/.txt/.crash 文件")
        merged = []
        ok = 0
        for fp in files:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    recs = _parse_kiro_text(f.read())
            except (ValueError, OSError, json.JSONDecodeError) as e:
                logger.warning(f"跳过 {fp}: {e}")
                continue
            merged.extend(recs)
            ok += 1
        logger.info(f"目录合并：{ok}/{len(files)} 个文件，共 {len(merged)} 条记录")
        if not merged:
            raise ValueError(f"目录 {raw} 下没有解析出任何记录")
        return merged

    if is_file:
        with open(raw, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        text = raw
    return _parse_kiro_text(text)


def kiro_records_to_refresh_tokens(records: list, provider_override: str = "") -> list:
    """从 kiro 账号记录提取 [{refreshToken, clientId, clientSecret, provider}] 数组，按 refreshToken 去重。
    没有 refreshToken 的记录会被跳过。provider_override 非空时覆盖全部 provider。
    兼容多种结构：
      - v1.6.6 新结构（refreshToken / clientId / clientSecret 在 credentials.* / idp 在顶层）
      - 驼峰 (refreshToken/clientId/clientSecret) 与下划线 (refresh_token/client_id/client_secret) 两种键名
    IDC / BuilderId 账号刷新 token 必须带 clientId/clientSecret，所以两者一并带出（缺失时置空串）。
    """
    out = []
    seen = set()
    for rec in records:
        if not isinstance(rec, dict):
            continue
        creds = rec.get("credentials") if isinstance(rec.get("credentials"), dict) else {}

        def _pick(*keys):
            for k in keys:
                v = rec.get(k) or creds.get(k)
                if v:
                    return v
            return ""

        tok = _pick("refreshToken", "refresh_token")
        if not tok or tok in seen:
            continue
        seen.add(tok)
        prov = (
            provider_override
            or rec.get("provider")
            or creds.get("provider")
            or rec.get("idp")
            or "Google"
        )
        out.append({
            "refreshToken": tok,
            "clientId": _pick("clientId", "client_id"),
            "clientSecret": _pick("clientSecret", "client_secret"),
            "provider": prov,
        })
    return out


def build_kiro_record_from_refresh(refresh_token: str, provider: str = "Google",
                                    label: str = "", email: str = "",
                                    password=None, client_id=None,
                                    client_secret=None, region=None) -> dict:
    """从 refreshToken+provider 生成完整 kiro.json 条目骨架。
    缺失字段（accessToken/userId/profileArn/usageData 等）置空/null，
    待 Kiro 首次用 refreshToken 换 access_token 时由其自身填充。
    结构对齐 register_kiro 的 social 分支（见 ~line 4251）。
    Builder ID 卡密带 client_id/client_secret/region 时会回填（用于 BuilderId 账号）。
    """
    provider_display = provider or "Google"
    return {
        "id": str(uuid.uuid4()),
        "email": email,
        "password": password,
        "label": label or f"Kiro {provider_display} 账号",
        "status": "active",
        "addedAt": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
        "accessToken": "",
        "refreshToken": refresh_token,
        "expiresAt": None,
        "provider": provider_display,
        "userId": None,
        "authMethod": "social",
        "clientId": client_id,
        "clientSecret": client_secret,
        "region": region,
        "clientIdHash": None,
        "ssoSessionId": None,
        "idToken": None,
        "startUrl": None,
        "profileArn": None,
        "usageData": None,
        "groupId": None,
        "tagLinks": [],
        "machineId": str(uuid.uuid4()),
    }


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _normalize_refresh_item(item) -> dict:
    if not isinstance(item, dict):
        raise ValueError(f"非对象记录: {item!r}")
    tok = item.get("refreshToken") or item.get("refresh_token")
    if not tok:
        raise ValueError(f"缺少 refreshToken 字段: {item!r}")
    provider = item.get("provider")
    if not provider:
        # 带 client 凭证的多为 Builder ID 卡密，否则默认 Google
        provider = "BuilderId" if item.get("clientSecret") else "Google"
    out = {"refreshToken": tok, "provider": provider}
    if item.get("email"):
        out["email"] = item["email"]
    if item.get("password") is not None:
        out["password"] = item["password"]
    for k in ("clientId", "clientSecret", "region"):
        if item.get(k):
            out[k] = item[k]
    return out


def _parse_prefixed_token_line(line: str) -> dict:
    """解析一行，支持前缀 metadata + {JSON}。

    支持形态:
      - '{"refreshToken": "...", "provider": "Google"}'                 # 纯 JSON
      - '20 user@x.com|pwd|totp {"refreshToken": "..."}'                # 序号+email|pwd|totp+JSON
      - 'user@x.com\\tpwd\\t{"refreshToken": "..."}'                    # Tab 分隔
      - 'aor...xxxxx'                                                    # 裸 token
    前缀里有 email 就用 email，有 '|' 分段且第二段非邮箱时当作 password。
    """
    line = line.strip().rstrip(",")
    brace = line.find("{")
    if brace == -1:
        return {"refreshToken": line, "provider": "Google"}

    prefix = line[:brace].strip()
    item = _normalize_refresh_item(json.loads(line[brace:]))
    if not prefix:
        return item

    m = _EMAIL_RE.search(prefix)
    if m:
        item.setdefault("email", m.group(0))

    if "|" in prefix:
        parts = [p.strip() for p in prefix.split("|")]
        if len(parts) >= 2 and parts[1] and not _EMAIL_RE.fullmatch(parts[1]):
            item.setdefault("password", parts[1])
    return item


def _parse_kiro_card_line(line: str) -> dict:
    """解析 ----分隔的卡密导出行（Builder ID 卡密）。

    典型 5 段: email----password----refreshToken----clientId----clientSecret
    兼容 3 段: email----password----refreshToken（无 client 凭证）。

    用内容启发式定位字段，避免纯位置假设出错：
      - email：匹配邮箱正则
      - clientSecret：JWT（eyJ 开头、含两个 '.'）
      - refreshToken：kiro token（含 ':' 签名分隔）
      - 其余按出现顺序 → [password, clientId]
    含 clientSecret 时 provider 默认 BuilderId，否则 Google；可被 --provider 覆盖。
    """
    parts = [p.strip() for p in line.split("----") if p.strip()]
    if not parts:
        raise ValueError(f"空卡密行: {line!r}")

    email = ""
    refresh = ""
    client_secret = ""
    leftovers = []
    for p in parts:
        if not email and _EMAIL_RE.fullmatch(p):
            email = p
        elif not client_secret and p.startswith("eyJ") and p.count(".") >= 2:
            client_secret = p
        elif not refresh and ":" in p:
            refresh = p
        else:
            leftovers.append(p)

    # 位置兜底：没靠特征认出 refreshToken 时取第 3 段
    if not refresh:
        if len(parts) >= 3:
            refresh = parts[2]
            leftovers = [p for p in leftovers if p != refresh]
        elif leftovers:
            refresh = leftovers.pop(0)
    if not refresh:
        raise ValueError(f"卡密缺少 refreshToken: {line[:60]!r}")

    password = leftovers[0] if len(leftovers) >= 1 else None
    client_id = leftovers[1] if len(leftovers) >= 2 else ""

    item = {
        "refreshToken": refresh,
        "provider": "BuilderId" if client_secret else "Google",
    }
    if email:
        item["email"] = email
    if password is not None:
        item["password"] = password
    if client_id:
        item["clientId"] = client_id
    if client_secret:
        item["clientSecret"] = client_secret
        item["region"] = "us-east-1"  # Builder ID OIDC 固定 us-east-1
    return item


_KIRO_BLOCK_HEADER_RE = re.compile(r"^(?:📦\s*)?Account\s*#?\d+\s*$", re.IGNORECASE)
_KIRO_BLOCK_FIELD_RE = re.compile(r"^(?:🔸\s*)?(mail|pass|2fa)\s*[:：]\s*(.*)$", re.IGNORECASE)


def _parse_kiro_account_blocks(content: str) -> list:
    """解析 📦 Account 块导出格式（kiro/0611=03.txt）。

    块布局（`---` 分隔线可有可无，遇到下一个 📦 Account 头即切块）：
        📦 Account #12
        🔸 mail: RefreshToken            # 类型标记，非真实邮箱，忽略
        🔸 pass: aor...:MGUC...          # 实际的 refreshToken
        🔸 2fa: xxx@gmail.com            # 实际的邮箱（可缺省）
    mail/2fa 字段值是邮箱形态时才认作 email。
    返回 [{refreshToken, provider, email?}]，无 pass 字段的块跳过。
    """
    items: list = []
    cur: "dict | None" = None

    def _flush():
        nonlocal cur
        if cur and cur.get("refreshToken"):
            items.append(cur)
        cur = None

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or re.fullmatch(r"[-—–]{2,}", line):
            continue
        if _KIRO_BLOCK_HEADER_RE.match(line):
            _flush()
            cur = {"provider": "Google"}
            continue
        m = _KIRO_BLOCK_FIELD_RE.match(line)
        if not m:
            continue
        if cur is None:
            cur = {"provider": "Google"}
        key, val = m.group(1).lower(), m.group(2).strip()
        if key == "pass" and val:
            cur["refreshToken"] = val
        elif key in ("mail", "2fa") and _EMAIL_RE.fullmatch(val):
            cur.setdefault("email", val)
    _flush()
    return items


def parse_refresh_token_input(raw: str, is_file: bool) -> list:
    """把多种输入解析为 [{refreshToken, provider, email?, password?}] 列表。
    支持：
      - JSON 数组：[{"refreshToken": "...", "provider": "Google"}, ...]
      - 单个 JSON 对象
      - 每行一个 JSON 对象（结尾逗号容忍）
      - 每行 '<idx> <email>|<password>|<totp> {JSON}' 富格式
      - 📦 Account 块格式（mail/pass/2fa 标签，pass 为 refreshToken）
      - 每行一个裸 refreshToken 字符串（默认 provider=Google）
    """
    if is_file:
        with open(raw, "r", encoding="utf-8") as f:
            content = f.read()
    else:
        content = raw
    content = content.strip()
    if not content:
        return []

    if content.startswith("["):
        data = json.loads(content)
        if not isinstance(data, list):
            raise ValueError("JSON 顶层不是数组")
        return [_normalize_refresh_item(x) for x in data]

    if content.startswith("{"):
        try:
            return [_normalize_refresh_item(json.loads(content))]
        except json.JSONDecodeError:
            pass  # 多行 JSON，回退到逐行解析

    # 📦 Account 块格式：出现 Account 头或 pass: 标签行即按块解析
    if any(
        _KIRO_BLOCK_HEADER_RE.match(l.strip())
        or re.match(r"^(?:🔸\s*)?pass\s*[:：]", l.strip(), re.IGNORECASE)
        for l in content.splitlines()
    ):
        blocks = _parse_kiro_account_blocks(content)
        if blocks:
            return blocks

    items = []
    for line in content.splitlines():
        line = line.strip().rstrip(",")
        if not line or line.startswith("#"):
            continue
        # ----分隔且不含 JSON 的行视为卡密导出（Builder ID 卡密）
        if "----" in line and "{" not in line:
            items.append(_parse_kiro_card_line(line))
        else:
            items.append(_parse_prefixed_token_line(line))
    return items


def append_kiro_record(record: dict, output_file: str = KIRO_OUTPUT_FILE):
    """把记录追加到 kiro.json（维护一个 JSON 数组）。
    原子写：先写 .tmp，fsync 后 os.replace；中断不会留半截文件。
    """
    existing = []
    if os.path.isfile(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
        except Exception as e:
            logger.warning(f"{output_file} 解析失败，将重建: {e}")
            existing = []
    existing.append(record)

    tmp_path = f"{output_file}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, output_file)
    logger.info(f"已追加到 {output_file}（共 {len(existing)} 条）")


