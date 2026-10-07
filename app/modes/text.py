"""文本/文件处理 mode：format、diff、suspend、extract、tokens、disabled"""

import json
import logging
import os
import re
import sys
import urllib.error
import urllib.request

from app.accounts.claude import check_mail_suspended
from app.core.parsing import parse_account_input, split_input
from app.kiro.parsing import parse_kiro_input, parse_labeled_blocks
from app.settings import OAUTH_ADMIN_API_BASE_URL, OAUTH_ADMIN_API_TOKEN, OAUTH_ADMIN_API_REFRESH_TOKEN

logger = logging.getLogger(__name__)


# format 模式：规范化账号文件 → email----password----totp_secret
async def run_format(mode: str, raw_input: str, is_file: bool):
    if not is_file:
        print(f"format 需要传入文件路径，got: {raw_input}")
        exit(1)
    # 解析 --write / --out <path>
    extra = sys.argv[3:]
    out_write_inplace = "--write" in extra
    out_path = None
    if "--out" in extra:
        i = extra.index("--out")
        if i + 1 >= len(extra):
            print("--out 需要一个文件路径参数")
            exit(1)
        out_path = extra[i + 1]

    with open(raw_input, "r") as f:
        content = f.read()

    # 块格式：含有 "账号：" 标签、"==== ... ====" 分隔线、或纯分隔符行
    # (---、———、——— 等) 时，按多行块解析（忽略行首序号、接收邮箱等额外字段）
    block_mode = (
        bool(re.search(r"^\s*账号\s*[:：]", content, re.MULTILINE))
        or bool(re.search(r"^=+.*=+$", content, re.MULTILINE))
        or bool(re.search(r"^[\-—–_=─━]{2,}$", content, re.MULTILINE))
    )

    if block_mode:
        triples, total = parse_labeled_blocks(content)
        ok = len(triples)
        bad = total - ok
        out_lines = [f"{e}----{p}----{t}" for e, p, t in triples]
        if bad > 0:
            out_lines.append(f"# WARN: 共识别 {total} 块，成功解析 {ok} 条，丢弃 {bad} 块（字段不全）")
    else:
        out_lines = []
        ok = 0
        bad = 0
        for ln in content.splitlines():
            stripped = ln.rstrip("\r\n")
            if not stripped.strip():
                out_lines.append("")
                continue
            if stripped.lstrip().startswith("#"):
                out_lines.append(stripped)
                continue
            try:
                parsed = parse_kiro_input(stripped)
                if parsed[0] == "idc":
                    _, start_url, username, temp_pwd, new_pwd = parsed
                    out_lines.append(
                        f"idc::{start_url}----{username}----{temp_pwd}----{new_pwd}"
                    )
                else:
                    _, email, password, totp = parsed
                    out_lines.append(f"{email}----{password}----{totp}")
                ok += 1
            except Exception as e:
                out_lines.append(f"# INVALID: {stripped}  // {e}")
                bad += 1

    output = "\n".join(out_lines) + ("\n" if out_lines else "")

    if out_write_inplace:
        with open(raw_input, "w") as f:
            f.write(output)
        print(f"已覆盖写回 {raw_input}（成功 {ok} / 非法 {bad}）")
    elif out_path:
        with open(out_path, "w") as f:
            f.write(output)
        print(f"已写到 {out_path}（成功 {ok} / 非法 {bad}）")
    else:
        # 预览到 stdout
        print(output, end="")
        print(f"# ---- 预览结束（成功 {ok} / 非法 {bad}），加 --write 覆盖或 --out <path> 写新文件 ----")
    return


# diff 模式：对比账号文件与 sub2api 导出 JSON，找出缺失账号
async def run_diff(mode: str, raw_input: str, is_file: bool):
    if len(sys.argv) < 4:
        print("用法: python main.py diff <账号文件> <sub2api-account.json>")
        exit(1)
    accounts_file = sys.argv[2]
    json_file = sys.argv[3]
    if not os.path.isfile(accounts_file):
        print(f"账号文件不存在: {accounts_file}")
        exit(1)
    if not os.path.isfile(json_file):
        print(f"JSON 文件不存在: {json_file}")
        exit(1)

    # 读取 JSON 中已存在的 email
    with open(json_file) as f:
        data = json.load(f)
    json_emails = set()
    for acc in data.get("accounts", []):
        em = (acc.get("credentials", {}).get("email_address")
              or acc.get("extra", {}).get("email_address")
              or acc.get("name"))
        if em:
            json_emails.add(em.lower())

    # 读取账号文件
    account_lines = []
    with open(accounts_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            email = split_input(line)[0].strip()
            account_lines.append((email, line))

    missing = [(em, raw) for em, raw in account_lines if em.lower() not in json_emails]

    print("\n" + "=" * 60)
    print("账号对比结果")
    print("=" * 60)
    print(f"\nJSON 中账号数: {len(json_emails)}")
    print(f"账号文件账号数: {len(account_lines)}")
    print(f"缺失账号数: {len(missing)}")

    if missing:
        print(f"\n--- 缺失账号 ({len(missing)}) ---")
        for em, _ in missing:
            print(f"  {em}")
        with open("missing.txt", "w") as f:
            for _, raw in missing:
                f.write(raw + "\n")
        print(f"\n缺失账号已保存到 missing.txt")
    print("=" * 60)
    return


# suspend 模式：批量检查账号是否被封禁
async def run_suspend(mode: str, raw_input: str, is_file: bool):
    if not is_file:
        print(f"文件不存在: {raw_input}")
        exit(1)
    with open(raw_input, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    logger.info(f"读取到 {len(lines)} 个账号，开始批量检查封禁状态...")

    results = []
    for idx, line in enumerate(lines, 1):
        try:
            email, password = parse_account_input(line)
        except ValueError as e:
            logger.warning(f"[{idx}/{len(lines)}] 解析失败: {e}")
            results.append({"email": line[:30], "status": "解析失败"})
            continue

        logger.info(f"[{idx}/{len(lines)}] 检查: {email}")
        status, _ = check_mail_suspended(email, password)
        logger.info(f"[{idx}/{len(lines)}] {email}: {status}")
        results.append({"email": email, "password": password, "status": status, "raw": line})

    # 汇总
    suspended = [r for r in results if r["status"] == "已封禁"]
    normal = [r for r in results if r["status"] == "正常"]
    errors = [r for r in results if r["status"] not in ("已封禁", "正常")]

    print("\n" + "=" * 60)
    print("封禁检查结果汇总")
    print("=" * 60)
    print(f"\n总计: {len(results)}  正常: {len(normal)}  已封禁: {len(suspended)}  异常: {len(errors)}")

    if suspended:
        print(f"\n--- 已封禁账号 ({len(suspended)}) ---")
        for r in suspended:
            print(f"  {r['email']}")
        with open("suspended.txt", "w") as f:
            for r in suspended:
                f.write(r["raw"] + "\n")
        print(f"\n已封禁账号已保存到 suspended.txt")

    if normal:
        with open("normal.txt", "w") as f:
            for r in normal:
                f.write(r["raw"] + "\n")
        print(f"正常账号已保存到 normal.txt ({len(normal)})")

    if errors:
        print(f"\n--- 异常账号 ({len(errors)}) ---")
        for r in errors:
            print(f"  {r['email']}  ({r['status']})")
    print("=" * 60)
    return


# extract 模式：从 session.txt 提取 sessionKey 到 sessionkey.txt
async def run_extract(mode: str, raw_input: str, is_file: bool):
    if not is_file:
        print(f"文件不存在: {raw_input}")
        exit(1)
    with open(raw_input, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]

    output_file = "sessionkey.txt"
    keys = []
    for line in lines:
        parts = split_input(line)
        # 查找 sk-ant- 开头的字段作为 sessionKey
        session_key = None
        for part in parts:
            part = part.strip()
            if part.startswith("sk-ant-"):
                session_key = part
                break
        if session_key:
            keys.append(f"sessionKey={session_key}")
        else:
            logger.warning(f"未找到 sessionKey: {line[:50]}...")

    with open(output_file, "w") as f:
        f.write("\n".join(keys) + "\n")

    logger.info(f"已从 {raw_input} 提取 {len(keys)} 个 sessionKey 到 {output_file}")
    for k in keys:
        print(k)
    return


# tokens 模式：从任意格式提取 sk-ant 开头的 key，仅保留 key 本身
async def run_tokens(mode: str, raw_input: str, is_file: bool):
    if not is_file:
        print(f"文件不存在: {raw_input}")
        exit(1)
    with open(raw_input, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]

    output_file = "tokens.txt"
    token_re = re.compile(r"sk-ant-(?:(?!----)\S)+")
    keys = []
    for line in lines:
        m = token_re.search(line)
        if m:
            keys.append(m.group(0))
        else:
            logger.warning(f"未找到 sk-ant key: {line[:50]}...")

    with open(output_file, "w") as f:
        f.write("\n".join(keys) + ("\n" if keys else ""))

    logger.info(f"已从 {raw_input} 提取 {len(keys)} 个 sk-ant key 到 {output_file}")
    for k in keys:
        print(k)
    return


# emails 模式：从任意格式（email----app_password----时间----sessionKey----uuid 等）
# 每行抽出第一段 email，输出纯邮箱格式（一行一个）。默认打印预览，不动原文件。
async def run_emails(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    out_write_inplace = "--write" in extra
    unique = "--unique" in extra
    out_path = None
    if "--out" in extra:
        i = extra.index("--out")
        if i + 1 >= len(extra):
            print("--out 需要一个文件路径参数")
            exit(1)
        out_path = extra[i + 1]

    if is_file:
        with open(raw_input, "r") as f:
            content = f.read()
    else:
        if not raw_input.strip():
            print("用法: python main.py emails <账号文件>            # 抽出纯邮箱(默认打印预览)")
            print("     python main.py emails <账号文件> --unique   # 去重(保序)")
            print("     python main.py emails <账号文件> --out emails.txt   # 写到新文件")
            print("     python main.py emails <账号文件> --write     # 覆盖原文件为纯邮箱列表")
            print("     python main.py emails 'a@b.com----pwd----...'        # 单条也支持")
            exit(1)
        content = raw_input

    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    emails = []
    seen = set()
    miss = 0
    for ln in content.splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s.startswith("<!--"):
            continue
        m = email_re.search(s)
        if not m:
            miss += 1
            logger.warning(f"未找到 email: {s[:50]}...")
            continue
        addr = m.group(0)
        if unique and addr in seen:
            continue
        seen.add(addr)
        emails.append(addr)

    output = "\n".join(emails) + ("\n" if emails else "")

    if out_write_inplace:
        if not is_file:
            print("--write 只能用于文件输入")
            exit(1)
        with open(raw_input, "w") as f:
            f.write(output)
        print(f"已覆盖写回 {raw_input}（{len(emails)} 个邮箱，未识别 {miss} 行）")
    elif out_path:
        with open(out_path, "w") as f:
            f.write(output)
        print(f"已写到 {out_path}（{len(emails)} 个邮箱，未识别 {miss} 行）")
    else:
        print(output, end="")
        print(f"# ---- 预览结束（{len(emails)} 个邮箱，未识别 {miss} 行），加 --write 覆盖或 --out <path> 写新文件 ----")
    return


# common 模式：对比两个文件，找出共同的邮箱
async def run_common(mode: str, raw_input: str, is_file: bool):
    if len(sys.argv) < 4:
        print("用法: python main.py common <文件A> <文件B>")
        print("  支持纯邮箱列表（一行一个）和 CSV（自动从各列提取邮箱）")
        print("  选项:")
        print("    --out <path>    结果写到文件（默认打印到终端）")
        print("    --only-a        只输出在 A 中有、B 中没有的邮箱")
        print("    --only-b        只输出在 B 中有、A 中没有的邮箱")
        print("    --with-pass     匹配到的邮箱带上密码一起输出（邮箱----密码，")
        print("                    密码从 email----password 格式的文件里取）")
        exit(1)

    file_a = sys.argv[2]
    file_b = sys.argv[3]
    for f in (file_a, file_b):
        if not os.path.isfile(f):
            print(f"文件不存在: {f}")
            exit(1)

    extra = sys.argv[4:]
    out_path = None
    if "--out" in extra:
        i = extra.index("--out")
        if i + 1 >= len(extra):
            print("--out 需要一个文件路径参数")
            exit(1)
        out_path = extra[i + 1]
    only_a = "--only-a" in extra
    only_b = "--only-b" in extra
    with_pass = "--with-pass" in extra

    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    # 识别 email----password / email:password / email,password 等成对格式
    pair_re = re.compile(
        r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
        r"\s*(?:----|:|\||,|\t)\s*(\S+)"
    )

    def _extract_emails(path: str) -> set[str]:
        with open(path, "r") as fh:
            text = fh.read()
        return {m.lower() for m in email_re.findall(text)}

    def _extract_pairs(path: str) -> dict[str, str]:
        """返回 {邮箱小写: 密码}，只收 email<分隔符>password 形式的行。"""
        pairs: dict[str, str] = {}
        with open(path, "r") as fh:
            for line in fh:
                m = pair_re.search(line)
                if m:
                    pairs.setdefault(m.group(1).lower(), m.group(2))
        return pairs

    set_a = _extract_emails(file_a)
    set_b = _extract_emails(file_b)

    pw_map: dict[str, str] = {}
    if with_pass:
        # B 优先（通常密码库是第二个文件），A 补齐
        pw_map = _extract_pairs(file_a)
        pw_map.update(_extract_pairs(file_b))

    name_a = os.path.basename(file_a)
    name_b = os.path.basename(file_b)

    if only_a:
        result = sorted(set_a - set_b)
        label = f"仅在 {name_a} 中（{name_b} 没有）"
    elif only_b:
        result = sorted(set_b - set_a)
        label = f"仅在 {name_b} 中（{name_a} 没有）"
    else:
        result = sorted(set_a & set_b)
        label = "两个文件共同的邮箱"

    print(f"\n{name_a}: {len(set_a)} 个邮箱")
    print(f"{name_b}: {len(set_b)} 个邮箱")
    print(f"交集: {len(set_a & set_b)}  仅A: {len(set_a - set_b)}  仅B: {len(set_b - set_a)}")
    print(f"\n--- {label} ({len(result)}) ---")

    if with_pass:
        lines = []
        missing = 0
        for e in result:
            pw = pw_map.get(e)
            if pw:
                lines.append(f"{e}----{pw}")
            else:
                lines.append(e)
                missing += 1
        if missing:
            print(f"（{missing} 个邮箱没找到对应密码，只输出邮箱）")
    else:
        lines = list(result)

    output = "\n".join(lines) + ("\n" if lines else "")
    if out_path:
        with open(out_path, "w") as fh:
            fh.write(output)
        print(f"已写到 {out_path}")
    else:
        for ln in lines:
            print(f"  {ln}")
    return


def _oauth_admin_refresh(base_url: str, refresh_token: str) -> str | None:
    """用 refresh_token 刷新 access_token，返回新 token 或 None。"""
    url = f"{base_url}/api/auth/refresh"
    req = urllib.request.Request(
        url,
        data=b"",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Cookie": f"refresh_token={refresh_token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            data = json.loads(text)
            token = (data.get("accessToken")
                     or data.get("access_token")
                     or data.get("token")
                     or (data.get("data") or {}).get("accessToken")
                     or (data.get("data") or {}).get("access_token"))
            if token:
                logger.info("refresh_token 刷新成功，已获取新 access_token")
                return token
            # 尝试从 Set-Cookie 头提取
            for val in (resp.headers.get_all("Set-Cookie") or []):
                if "access_token=" in val or "token=" in val:
                    for part in val.split(";"):
                        k, _, v = part.strip().partition("=")
                        if k in ("access_token", "token") and v:
                            logger.info("从 Set-Cookie 获取新 access_token")
                            return v
            logger.warning(f"refresh 响应中未找到 token: {text[:300]}")
            return None
    except Exception as e:
        logger.warning(f"refresh_token 刷新失败: {e}")
        return None


def _oauth_admin_request(base_url: str, path: str, token: str,
                          refresh_token: str = "", params: dict = None) -> tuple:
    """向 oauth admin API 发 GET 请求，返回 (parsed_json, raw_text)。token 过期时自动刷新。"""
    qs = urllib.parse.urlencode(params) if params else ""
    url = f"{base_url}{path}{'?' + qs if qs else ''}"
    headers = {"Accept": "application/json"}
    if token:
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        headers["Authorization"] = f"Bearer {token}"
    if refresh_token:
        headers["Cookie"] = f"refresh_token={refresh_token}"

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return json.loads(text), text
    except urllib.error.HTTPError as e:
        status = e.code
        err_text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        if status == 401 and refresh_token:
            new_token = _oauth_admin_refresh(base_url, refresh_token)
            if new_token:
                return _oauth_admin_request(base_url, path, new_token, "", params)
        raise RuntimeError(f"请求失败 [{status}]: {err_text[:500]}")


def _oauth_admin_write(base_url: str, path: str, token: str, body: dict,
                       refresh_token: str = "", method: str = "PATCH") -> tuple:
    """向 oauth admin API 发写请求（默认 PATCH），返回 (parsed_json_or_None, raw_text)。
    token 过期（401）时用 refresh_token 刷新后自动重试一次。"""
    url = f"{base_url}{path}"
    data = json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token:
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        headers["Authorization"] = f"Bearer {token}"
    if refresh_token:
        headers["Cookie"] = f"refresh_token={refresh_token}"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            try:
                return json.loads(text), text
            except json.JSONDecodeError:
                return None, text
    except urllib.error.HTTPError as e:
        status = e.code
        err_text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        if status == 401 and refresh_token:
            new_token = _oauth_admin_refresh(base_url, refresh_token)
            if new_token:
                return _oauth_admin_write(base_url, path, new_token, body, "", method)
        raise RuntimeError(f"请求失败 [{status}]: {err_text[:500]}")


def _resolve_admin_tokens(raw_input: str):
    """统一解析 admin API 的 access_token / refresh_token / base_url（disabled 系模式共用）。
    返回 (base_url, access_token, refresh_token)；缺凭据时打印用法并退出。"""
    refresh_token = OAUTH_ADMIN_API_REFRESH_TOKEN
    access_token = OAUTH_ADMIN_API_TOKEN
    # 命令行第一个非 -- 开头的参数视为 bearer token 覆盖
    arg_tok = raw_input.strip()
    if arg_tok and not arg_tok.startswith("--"):
        access_token = arg_tok

    if not access_token and not refresh_token:
        print("需要后台 admin API 凭据。在 config.py 中配置（推荐 refresh_token，有效期 7 天）:")
        print('    OAUTH_ADMIN_API_REFRESH_TOKEN = "eyJ..."')
        print("  或配置 access_token（有效期 15 分钟）:")
        print('    OAUTH_ADMIN_API_TOKEN = "eyJ..."')
        exit(1)

    base_url = OAUTH_ADMIN_API_BASE_URL.rstrip("/")
    if not access_token and refresh_token:
        logger.info("无 access_token，使用 refresh_token 刷新...")
        access_token = _oauth_admin_refresh(base_url, refresh_token)
        if not access_token:
            print("refresh_token 刷新失败，请检查 token 是否过期")
            exit(1)
    return base_url, access_token, refresh_token


def _fetch_disabled_accounts(base_url: str, access_token: str, refresh_token: str):
    """分页拉取全部已停用账号，返回 (accounts_list, api_total)。"""
    page = 1
    page_size = 100
    all_disabled = []
    total_accounts = 0

    logger.info("开始查询已停用的 OAuth 账号...")
    while True:
        params = {
            "page_mode": 1,
            "page": page,
            "page_size": page_size,
            "status": "disabled",
            "recovery_window": "all",
            "fable_recovery_window": "all",
            "sort": "created_at",
            "direction": "desc",
        }
        data, raw = _oauth_admin_request(base_url, "/api/admin/oauth-accounts",
                                          access_token, refresh_token, params)
        if isinstance(data, dict):
            accounts = data.get("data") or data.get("accounts") or []
            total_accounts = data.get("total", total_accounts)
        elif isinstance(data, list):
            accounts = data
            total_accounts = len(accounts)
        else:
            raise RuntimeError(f"无法解析响应: {raw[:500]}")

        if not accounts:
            break
        all_disabled.extend(accounts)
        logger.info(f"第 {page} 页: 获取 {len(accounts)} 条（累计 {len(all_disabled)}）")
        if len(accounts) < page_size:
            break
        page += 1
    return all_disabled, total_accounts


# disabled 模式：从 oauth-accounts admin API 获取已停用的账号
async def run_disabled(mode: str, raw_input: str, is_file: bool):
    base_url, access_token, refresh_token = _resolve_admin_tokens(raw_input)
    try:
        all_disabled, total_accounts = _fetch_disabled_accounts(
            base_url, access_token, refresh_token)
    except RuntimeError as e:
        print(str(e))
        exit(1)

    print("\n" + "=" * 60)
    print("OAuth 已停用账号查询")
    print("=" * 60)
    if total_accounts:
        print(f"\n已停用账号数: {len(all_disabled)}（API total={total_accounts}）")
    else:
        print(f"\n已停用账号数: {len(all_disabled)}")

    if all_disabled:
        print(f"\n--- 已停用账号 ({len(all_disabled)}) ---")
        for acc in all_disabled:
            name = acc.get("name") or acc.get("email") or acc.get("id", "?")
            status = acc.get("status", "")
            notes = acc.get("notes", "")
            line = f"  {name}  (status={status})"
            if notes:
                line += f"  [{notes}]"
            print(line)

        out_file = "disabled_accounts.txt"
        with open(out_file, "w") as f:
            for acc in all_disabled:
                f.write(json.dumps(acc, ensure_ascii=False) + "\n")
        print(f"\n已停用账号详情已保存到 {out_file}")

        emails_file = "disabled_emails.txt"
        emails = []
        for acc in all_disabled:
            email = acc.get("email") or (acc.get("canonical_identity") or {}).get("email", "")
            if email:
                emails.append(email)
        with open(emails_file, "w") as f:
            f.write("\n".join(emails) + ("\n" if emails else ""))
        print(f"已停用邮箱列表已保存到 {emails_file}（{len(emails)} 个）")
    else:
        print("\n未发现已停用的账号。")
    print("=" * 60)
    return


# disabled-unproxy 模式：把所有已停用账号的出站代理改为“无代理”(outbound_proxy_id=null)
async def run_disabled_unproxy(mode: str, raw_input: str, is_file: bool):
    args = sys.argv[2:]
    dry_run = "--dry-run" in args
    assume_yes = ("--yes" in args) or ("-y" in args)

    base_url, access_token, refresh_token = _resolve_admin_tokens(raw_input)
    try:
        all_disabled, total_accounts = _fetch_disabled_accounts(
            base_url, access_token, refresh_token)
    except RuntimeError as e:
        print(str(e))
        exit(1)

    # 只处理当前仍挂着代理的账号（outbound_proxy_id 非空），已是无代理的跳过
    targets = [a for a in all_disabled if a.get("outbound_proxy_id")]
    skipped_noproxy = len(all_disabled) - len(targets)

    print("\n" + "=" * 60)
    print("已停用账号 → 改为无代理")
    print("=" * 60)
    print(f"\n已停用账号数: {len(all_disabled)}"
          + (f"（API total={total_accounts}）" if total_accounts else ""))
    print(f"其中仍挂代理、待改为无代理: {len(targets)}；已是无代理跳过: {skipped_noproxy}")

    if not targets:
        print("\n没有需要处理的账号。")
        print("=" * 60)
        return

    print(f"\n--- 待处理账号 ({len(targets)}) ---")
    for acc in targets:
        name = acc.get("name") or acc.get("email") or acc.get("id", "?")
        print(f"  {name}  proxy={acc.get('outbound_proxy_id')}")

    if dry_run:
        print("\n[dry-run] 仅预览，未发起任何修改。去掉 --dry-run 执行。")
        print("=" * 60)
        return

    if not assume_yes and sys.stdin.isatty():
        try:
            ans = input(f"\n确认把以上 {len(targets)} 个账号改为无代理？[y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans not in ("y", "yes"):
            print("已取消。")
            return

    ok, failed = 0, []
    for i, acc in enumerate(targets, 1):
        acc_id = acc.get("id")
        name = acc.get("name") or acc.get("email") or acc_id or "?"
        if not acc_id:
            failed.append((name, "缺少 id"))
            continue
        # 保留账号现有限流配置，仅把出站代理置空；缺失字段回退到后台默认值
        payload = {
            "max_rpm": acc.get("max_rpm", 100),
            "max_tpm": acc.get("max_tpm", 8000000),
            "max_concurrent": acc.get("max_concurrent", 20),
            "max_sessions": acc.get("max_sessions", 100),
            "outbound_proxy_id": None,
        }
        try:
            _oauth_admin_write(base_url, f"/api/admin/oauth-accounts/{acc_id}",
                               access_token, payload, refresh_token, "PATCH")
            ok += 1
            logger.info(f"[{i}/{len(targets)}] {name} 已改为无代理")
        except RuntimeError as e:
            failed.append((name, str(e)))
            logger.warning(f"[{i}/{len(targets)}] {name} 改无代理失败: {e}")

    print("\n" + "=" * 60)
    print(f"完成：成功 {ok}/{len(targets)}，失败 {len(failed)}")
    if failed:
        for name, reason in failed:
            print(f"  失败 {name}: {reason}")
    print("=" * 60)
    return
