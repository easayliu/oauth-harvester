"""AWS 相关 mode：aws-diag 诊断、aws 批量登录、aws-claude 开通 Claude Platform、aws-kiro 自动建 IDC 用户"""

import asyncio
import json
import logging
import os
import re
import secrets
import string
import sys

from app.accounts.aws import AWS_OUTPUT_FILE, aws_diagnose_account, login_aws, login_aws_claude
from app.accounts.aws_idc import aws_idc_open_console, provision_idc_user_on_page
from app.accounts.aws_idc_api import (
    KIRO_SUBSCRIPTION_DEFAULT,
    idc_create_application_assignment,
    idc_find_group_id,
    idc_find_or_create_group,
    idc_list_instance,
    idc_list_kiro_profile_apps,
    idc_list_users,
    idc_portal_url,
    provision_idc_user_api,
    q_create_assignment,
)
from app.kiro.api import kiro_list_first_profile_arn
from app.accounts.aws_quota import aws_fetch_quotas
from app.core.browser import (
    aws_session_state_path,
    cloak_browser_session,
    kiro_browser_backend,
    new_window_sized_context,
    save_aws_session,
)
from app.core.parsing import parse_aws_input, read_aws_records
from app.accounts.newapi import (
    newapi_model_mapping_for_geo,
    newapi_model_mapping_for_region,
    register_newapi_channel,
)
from app.accounts.subus import aws_region_to_geo
from app.settings import (
    AWS_IDC_EMAIL_DOMAIN,
    AWS_IDC_GROUP,
    AWS_IDC_INSTANCE_ID,
    AWS_IDC_KIRO_OUTPUT_FILE,
    AWS_IDC_REGION,
    AWS_IDC_USERNAME,
    NEWAPI_DEFAULT_GROUP,
    NEWAPI_GLOBAL_SOURCE_REGION,
    NEWAPI_NAME_PREFIX,
    NEWAPI_REGIONS,
)
import time

logger = logging.getLogger(__name__)


def _session_reuse_enabled() -> bool:
    """AWS 系列默认复用已保存的登录会话；命令行带 --no-session 则禁用（每次全新登录）。"""
    return "--no-session" not in sys.argv[2:]


def _ctx_state_path(email: str):
    """返回该 admin 的会话文件路径（复用开启且文件存在时），否则 None（全新会话）。"""
    if not _session_reuse_enabled() or not email:
        return None
    p = aws_session_state_path(email)
    return p if os.path.exists(p) else None


# aws-diag 模式：用 AK/SK 诊断账号，区分"权限不足"与"账号被限制"（不开浏览器）
async def run_aws_diag(mode: str, raw_input: str, is_file: bool):
    lines = read_aws_records(raw_input, is_file)
    if not lines:
        print("无可诊断的行")
        exit(0)

    verdict_label = {
        "ak_invalid": "AK/SK 无效",
        "root_no_federation": "Root AK（不支持联邦登录）",
        "federation_denied": "联邦权限不足（IAM）",
        "account_restricted": "账号被 AWS 限制（需开 support case / 换号）",
        "ok": "正常",
        "error": "诊断出错",
    }
    logger.info(f"开始诊断 {len(lines)} 个 AWS 账号...")
    results = []
    for idx, line in enumerate(lines, 1):
        try:
            email, _pwd, _totp, akid, sak, _region = parse_aws_input(line)
        except ValueError as e:
            logger.warning(f"[{idx}/{len(lines)}] 解析失败: {e}")
            results.append({"email": line[:40], "verdict": "error",
                            "steps": [{"step": "parse", "ok": False, "error": str(e)}]})
            continue
        if not akid or not sak:
            logger.warning(f"[{idx}/{len(lines)}] {email}: 缺 AK/SK，跳过（aws-diag 需要 AK/SK）")
            results.append({"email": email, "verdict": "error",
                            "steps": [{"step": "input", "ok": False, "error": "缺 AK/SK"}]})
            continue
        logger.info(f"[{idx}/{len(lines)}] 诊断 {email} (AKID={akid[:8]}...)")
        r = await asyncio.to_thread(aws_diagnose_account, akid, sak, email)
        results.append(r)
        for s in r.get("steps", []):
            flag = "✓" if s.get("ok") else "✗"
            extra = s.get("detail") or s.get("error") or ""
            logger.info(f"    {flag} {s['step']}  {extra}")
        logger.info(f"  → 结论: {verdict_label.get(r.get('verdict'), r.get('verdict'))}")

    print("\n" + "=" * 60)
    print("AWS 账号诊断结果汇总")
    print("=" * 60)
    from collections import Counter
    counts = Counter(r.get("verdict") for r in results)
    print(f"\n总计 {len(results)}:")
    for v, n in counts.most_common():
        print(f"  {verdict_label.get(v, v)}: {n}")
    bad = [r for r in results if r.get("verdict") != "ok"]
    if bad:
        print(f"\n--- 需关注 ({len(bad)}) ---")
        for r in bad:
            last_err = next((s.get("error", "") for s in reversed(r.get("steps", []))
                             if not s.get("ok")), "")
            print(f"  [{verdict_label.get(r.get('verdict'), r.get('verdict'))}] {r.get('email')}  {last_err}")

    # 模型 TPM / RPM 配额一览
    def _qfmt(v):
        if v is None:
            return "—"
        try:
            f = float(v)
            return f"{int(f):,}" if f.is_integer() else f"{f:,}"
        except Exception:
            return str(v)
    quota_rows = [r for r in results if r.get("quotas")]
    if quota_rows:
        print(f"\n--- 模型 TPM / RPM 配额 ---")
        for r in quota_rows:
            print(f"  {r.get('email', '')}")
            for m in ["Opus 4.7", "Sonnet 4.6", "Opus 4.6"]:
                mq = (r.get("quotas") or {}).get(m) or {}
                print(f"    {m:<11}  TPM={_qfmt(mq.get('tpm'))}   RPM={_qfmt(mq.get('rpm'))}")
    print("=" * 60)
    return


# AK：AKIA/ASIA + 16 位大写字母数字（两侧非字母数字，避免嵌在长串里误匹配）
_AK_SCAN_RE = re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])")
# SK：正好 40 位 base64（含内部 / +），两侧不接 base64 字符 → 排除 64 位恢复码/TOTP 等长串
_SK_SCAN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/=])")
# 二者合一，按出现顺序扫描，用于把每个 AK 与其后紧邻的 SK 配对
_AKSK_SCAN_RE = re.compile(
    r"(?P<ak>(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9]))"
    r"|(?P<sk>(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/=]))"
)
# 邮箱：用于把 AK 与文本里就近的邮箱关联（源文件里邮箱和 AK/SK 排布很乱）
_EMAIL_SCAN_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# 就近匹配邮箱的最大字符距离：超过则认为不属于同一条记录，不关联
_EMAIL_MAX_DIST = 250


def extract_ak_sk_pairs(text: str) -> tuple[list, list]:
    """从任意杂乱文本里抽 AK/SK 对：按出现顺序扫描，每个 AK 配其后紧邻的第一个 SK，
    并就近关联一个邮箱（文本里位置最近、且在 _EMAIL_MAX_DIST 以内的邮箱）。
    返回 (pairs, lone_aks)：pairs 是去重后的 [(akid, sak, email)]（同一 AK 保留首个 SK，
    email 找不到时为空串），lone_aks 是找到了 AK 却在下一个 AK 之前没配到 SK 的 AKID 列表。
    """
    # 预扫所有邮箱及其位置，供每个 AK 就近匹配
    emails = [(m.start(), m.group(0)) for m in _EMAIL_SCAN_RE.finditer(text)]

    def _nearest_email(lo: int, hi: int) -> str:
        """取离 [lo, hi]（AK起点~SK终点）最近的邮箱：落在跨度内距离记 0，
        否则取到两端的最小距离。邮箱通常紧跟 SK，故按跨度算比只按 AK 起点更准。"""
        best, best_d = "", None
        for epos, addr in emails:
            d = 0 if lo <= epos <= hi else min(abs(epos - lo), abs(epos - hi))
            if best_d is None or d < best_d:
                best_d, best = d, addr
        return best if best_d is not None and best_d <= _EMAIL_MAX_DIST else ""

    pairs: list[tuple[str, str, str]] = []
    seen_ak: set[str] = set()
    lone: list[str] = []
    pending_ak = None  # 已见到、尚未配到 SK 的 AK
    pending_pos = 0    # 该 AK 在文本中的起始位置（就近匹配邮箱用）
    for m in _AKSK_SCAN_RE.finditer(text):
        if m.group("ak"):
            if pending_ak is not None:
                lone.append(pending_ak)  # 上一个 AK 到这都没等到 SK
            pending_ak = m.group("ak")
            pending_pos = m.start()
        else:  # 命中 SK
            if pending_ak is not None:
                if pending_ak not in seen_ak:
                    seen_ak.add(pending_ak)
                    pairs.append((pending_ak, m.group("sk"), _nearest_email(pending_pos, m.end())))
                pending_ak = None
            # 无 pending_ak 的孤立 SK 直接忽略
    if pending_ak is not None:
        lone.append(pending_ak)
    # 去重孤立 AK，且排除其实已成功配对过的（同一 AK 可能多处出现）
    lone = [ak for ak in dict.fromkeys(lone) if ak not in seen_ak]
    return pairs, lone


# aws-extract 模式：从任意杂乱文本/文件里抽出所有 AK/SK 对，写成干净的 `AKID SAK` 每行一条，
# 可直接喂给 aws-quota / aws-diag。用法：python main.py aws-extract <file> [--out 输出文件]
async def run_aws_extract(mode: str, raw_input: str, is_file: bool):
    if is_file:
        with open(raw_input, "r", errors="ignore") as f:
            text = f.read()
    else:
        text = raw_input  # 也支持直接传一段文本
    out_path = _kiro_arg_val(sys.argv[3:], "--out", None) or (
        (raw_input + ".aksk.txt") if is_file else "aws_ak_sk.txt")

    pairs, lone = extract_ak_sk_pairs(text)
    if not pairs:
        print("未从输入中抽到任何 AK/SK 对")
        if lone:
            print(f"（发现 {len(lone)} 个没配到 SK 的 AK：{', '.join(lone[:5])}{' ...' if len(lone) > 5 else ''}）")
        exit(0)

    # 有邮箱写成 `email AKID SAK`（格式 B2），无邮箱写成 `AKID SAK`（格式 B），均可喂给 aws-quota
    with open(out_path, "w") as f:
        for akid, sak, email in pairs:
            f.write(f"{email} {akid} {sak}\n" if email else f"{akid} {sak}\n")

    with_email = sum(1 for _a, _s, e in pairs if e)
    print("\n" + "=" * 60)
    print("AK/SK 抽取结果")
    print("=" * 60)
    print(f"\n共抽到 {len(pairs)} 对（已按 AK 去重），其中 {with_email} 个关联到邮箱，写入 {out_path}")
    for akid, sak, email in pairs:
        tag = f"  <{email}>" if email else "  <无邮箱>"
        print(f"  {akid}  {sak[:4]}…{sak[-4:]}{tag}")
    if lone:
        print(f"\n--- 未配到 SK 的 AK ({len(lone)}) ---")
        for ak in lone:
            print(f"  {ak}")
    print(f"\n可直接查询配额：python main.py aws-quota {out_path}")
    print("=" * 60)
    return


# aws-quota 模式：用 AK/SK 直连 AWS API（纯 SigV4，不走 boto3/CLI）查配额。
# 输入同 aws-diag（需 AK/SK）。可选 --region <code>（默认 us-east-1，配额是分区域的）。
#   默认（简单）：查 EC2 + Bedrock，只打印关注的配额（EC2 On-Demand Standard、Opus RPM）；
#   --full（全量）：额外打印 EC2 的全部配额行（Bedrock 仍只打印关注的 Opus RPM）。
async def run_aws_quota(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    region = _kiro_arg_val(extra, "--region", "us-east-1") or "us-east-1"
    full = "--full" in extra
    # 服务配额组合（默认 EC2+Bedrock+Kiro）：
    #   默认      → ec2, bedrock, kiro（Kiro 仅信息展示，可用性看 EC2/Bedrock）
    #   --kiro    → 只查 kiro（跳过慢的 EC2/Bedrock）；可用性改看 Kiro overage>0，可用即标记写文件
    #   --no-kiro → ec2, bedrock（不查 kiro）
    # Kiro 配额 = Service Quotas service code=kiro，主要是每 profile 最大超额 L-75434B0B。
    kiro_only = "--kiro" in extra
    if kiro_only:
        service_codes = ("kiro",)
    elif "--no-kiro" in extra:
        service_codes = ("ec2", "bedrock")
    else:
        service_codes = ("ec2", "bedrock", "kiro")
    # 并发查询上限（默认 5）。AWS API 有限流，过高会被 Throttling，可用 --concurrency N 调整。
    try:
        concurrency = max(1, int(_kiro_arg_val(extra, "--concurrency", "5") or 5))
    except ValueError:
        concurrency = 5
    # 可用账号输出文件（EC2 或 Bedrock 关注配额 > 0 的账号），可用 --out 覆盖。
    out_available = _kiro_arg_val(extra, "--out", "aws_quota_available.txt") or "aws_quota_available.txt"
    lines = read_aws_records(raw_input, is_file)
    if not lines:
        print("无可查询的行")
        exit(0)

    def _qfmt(v):
        if v is None:
            return "—"
        try:
            f = float(v)
            return f"{int(f):,}" if f.is_integer() else f"{f:,}"
        except Exception:
            return str(v)

    # 只关心这些配额（每组关键词需全部命中，不区分大小写；全量仍在返回值里）：
    #   EC2:     Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances
    #   Bedrock: Claude Opus 4.6 / 4.7 / 4.8 的 RPM（requests per minute）
    HIGHLIGHTS = {
        "ec2": [["on-demand standard", "instances"]],
        "bedrock": [
            ["opus 4.6", "requests per minute"],
            ["opus 4.7", "requests per minute"],
            ["opus 4.8", "requests per minute"],
        ],
        "kiro": [["overage"]],  # Maximum allowed overage per Kiro profile (L-75434B0B)
    }

    def _match_highlight(name: str, groups: list) -> bool:
        low = (name or "").lower()
        return any(all(k in low for k in group) for group in groups)

    def _highlight_rows(code: str, quotas: list) -> list:
        groups = HIGHLIGHTS.get(code, [])
        return [q for q in quotas if _match_highlight(q.get("name"), groups)] if groups else quotas

    def _fmt_row(q: dict) -> str:
        adj = "可调" if q.get("adjustable") else "不可调"
        unit = q.get("unit") or ""
        if str(unit).lower() == "none":  # AWS 对计数型配额返回 Unit="None"，无意义
            unit = ""
        tail = f" {unit}" if unit else ""
        if q.get("is_default"):
            # 账号级 applied 未返回该配额，只有官方默认值——明确标注，不当作实际生效值
            return (f"{q.get('name')}: 无账号级值(默认 {_qfmt(q.get('default_value'))}{tail})"
                    f"  ({adj})")
        return f"{q.get('name')}: {_qfmt(q.get('value'))}{tail}  ({adj})"

    def _max_highlight_value(r: dict, code: str):
        """取某个服务关注配额里的最大值；查询失败/无有效值返回 None。"""
        if r.get("errors", {}).get(code):
            return None
        vals = []
        for q in _highlight_rows(code, r.get("quotas", {}).get(code, [])):
            try:
                vals.append(float(q.get("value")))
            except (TypeError, ValueError):
                continue
        return max(vals) if vals else None

    def _account_available(r: dict):
        """判断账号是否可用：
          --kiro 模式：看 Kiro overage（Maximum allowed overage per profile）> 0 → 可用（已提额）；
                       =0 → 不可用；查询失败/未取到 → None。
          默认模式：EC2（On-Demand Standard instances）或 Bedrock（Opus RPM）任一 > 0 → 可用。
        """
        if kiro_only:
            v = _max_highlight_value(r, "kiro")
            return None if v is None else v > 0
        vals = [v for v in (_max_highlight_value(r, "ec2"), _max_highlight_value(r, "bedrock"))
                if v is not None]
        if not vals:
            return None  # 两个服务都没拿到有效配额值
        return max(vals) > 0  # 任一服务关注配额 > 0 即视为可用

    def _label(r: dict) -> str:
        """账号标签：优先邮箱，其次 AK，避免汇总里出现空白行。"""
        return r.get("email") or r.get("akid") or r.get("account") or "(未知账号)"

    def _ident(r: dict) -> str:
        """账号标题行：显示 AK（或邮箱），account id 作为次要信息附在括号里。"""
        label = _label(r)
        acct = r.get("account") or ""
        return f"{label}  (account={acct})" if acct and acct != label else label

    def _print_service(code: str, quotas: list, err: str):
        if err:
            print(f"    [{code}] 查询失败: {err}")
            return
        # 全量模式打印全部配额行；但 bedrock 始终只打印关注的 Opus RPM 配额。
        # 简单模式对所有服务都只打印关注的配额。
        if full and code != "bedrock":
            rows = quotas
            print(f"    [{code}] 全部 {len(quotas)} 条：")
        else:
            rows = _highlight_rows(code, quotas)
            print(f"    [{code}] 关注 {len(rows)}/{len(quotas)} 条：")
        for q in rows:
            print(f"      {_fmt_row(q)}")
        if not rows:
            print("      （未匹配到关注的配额）")

    logger.info(f"开始查询 {len(lines)} 个账号的 {'/'.join(c.upper() for c in service_codes)} "
                f"配额（region={region}，{'全量' if full else '简单'}，并发={concurrency}）...")

    # 先解析全部行；解析失败/缺 AK 的直接落结果，其余交给并发 worker。
    results: list = [None] * len(lines)
    pending = []  # [(idx, email, akid, sak)]
    for idx, line in enumerate(lines):
        try:
            email, _pwd, _totp, akid, sak, _region = parse_aws_input(line)
        except ValueError as e:
            logger.warning(f"[{idx + 1}/{len(lines)}] 解析失败: {e}")
            results[idx] = {"email": line[:40], "ok": False, "error": f"解析失败: {e}"}
            continue
        if not akid or not sak:
            logger.warning(f"[{idx + 1}/{len(lines)}] {email}: 缺 AK/SK，跳过（aws-quota 需要 AK/SK）")
            results[idx] = {"email": email, "akid": akid, "ok": False, "error": "缺 AK/SK"}
            continue
        pending.append((idx, email, akid, sak))

    # 把关注配额拆成多行（写文件用，每行 `#` 前缀作注释，重新喂给 aws-quota 会被跳过）。
    def _result_lines(r: dict) -> list:
        out = []
        for code in service_codes:
            if r.get("errors", {}).get(code):
                out.append(f"{code}:查询失败")
                continue
            for q in _highlight_rows(code, r.get("quotas", {}).get(code, [])):
                if q.get("is_default"):
                    out.append(f"{q.get('name')}=无账号级值(默认 {_qfmt(q.get('default_value'))})")
                else:
                    out.append(f"{q.get('name')}={_qfmt(q.get('value'))}")
        return out or ["无关注配额"]

    # 实时写入：可用账号一发现就立即追加到 out_available（加锁串行化，避免并发写错乱）。
    write_lock = asyncio.Lock()
    written: list = []

    async def _write_available(r: dict) -> None:
        async with write_lock:
            try:
                with open(out_available, "a") as f:
                    f.write((r.get("line") or _label(r)) + "\n")
                    for ln in _result_lines(r):
                        f.write(f"#   {ln}\n")
                    f.write("\n")  # 记录间空行，便于阅读
                written.append(_label(r))
                logger.info(f"    ↳ 已实时写入可用账号 {_label(r)} → {out_available}（累计 {len(written)}）")
            except OSError as e:
                logger.warning(f"    ↳ 写入可用账号文件失败（{out_available}）: {e}")

    sem = asyncio.Semaphore(concurrency)

    async def _query(idx: int, email: str, akid: str, sak: str) -> None:
        async with sem:
            logger.info(f"[{idx + 1}/{len(lines)}] 查询 {email} (AKID={akid[:8]}...)")
            try:
                r = await asyncio.to_thread(aws_fetch_quotas, akid, sak, region, service_codes)
            except Exception as e:
                # 单个账号查询意外抛错（如重试耗尽的网络错误）不应中断其余账号的并发查询。
                logger.warning(f"    ✗ [{idx + 1}] {email}: 查询异常 {e}")
                r = {"ok": False, "account": "", "arn": "", "error": str(e), "quotas": {}, "errors": {}}
        r["email"] = email
        r["akid"] = akid
        r["line"] = lines[idx].strip()  # 原始输入行，便于把可用账号原样写回文件
        if r.get("ok"):
            r["available"] = _account_available(r)
            logger.info(f"    ✓ [{idx + 1}] account={r.get('account')}  available={r.get('available')}")
            if r.get("available") is True:
                await _write_available(r)  # 实时落盘，不等全部跑完
        else:
            logger.warning(f"    ✗ [{idx + 1}] {email}: {r.get('error')}")
        results[idx] = r

    await asyncio.gather(*(_query(*p) for p in pending))

    # 可用/不可用文案随模式变化：--kiro 看 overage，默认看 EC2/Bedrock。
    _avail_true = "kiro 可用" if kiro_only else "可用"
    _avail_reason = "kiro overage=0" if kiro_only else "EC2/Bedrock 配额均为 0"
    _avail_false_long = f"{'kiro 不可用' if kiro_only else '不可用'}（{_avail_reason}）"

    # 并发完成后按输入顺序打印每个成功账号的明细（避免并发时输出交错）。
    for r in results:
        if not r or not r.get("ok"):
            continue
        avail_txt = {True: _avail_true, False: _avail_false_long, None: "未知（配额未取到）"}[r.get("available")]
        print(f"\n  {_ident(r)}  ->  {avail_txt}")
        for code in service_codes:
            _print_service(code, r.get("quotas", {}).get(code, []),
                           r.get("errors", {}).get(code, ""))

    print("\n" + "=" * 60)
    print("AWS 配额查询结果汇总")
    print("=" * 60)
    ok = [r for r in results if r and r.get("ok")]
    bad = [r for r in results if r and not r.get("ok")]
    available = [r for r in ok if r.get("available") is True]
    unavailable = [r for r in ok if r.get("available") is False]
    print(f"\n总计 {len(results)}  成功: {len(ok)}  失败: {len(bad)}  "
          f"{_avail_true}: {len(available)}  不可用({_avail_reason}): {len(unavailable)}")
    if ok:
        print(f"\n--- 成功账号 ({len(ok)}) ---")
        for r in ok:
            avail = r.get("available")
            avail_txt = {True: _avail_true, False: "不可用", None: "未知"}[avail]
            print(f"  {_ident(r)}  ->  {avail_txt}")
            for code in service_codes:
                serr = r.get("errors", {}).get(code, "")
                if serr:
                    print(f"    [{code}] 查询失败: {serr}")
                    continue
                rows = _highlight_rows(code, r.get("quotas", {}).get(code, []))
                if rows:
                    for q in rows:
                        print(f"    [{code}] {_fmt_row(q)}")
                else:
                    print(f"    [{code}] （未匹配到关注的配额）")
    if available:
        print(f"\n--- {_avail_true}账号 ({len(available)}) ---")
        for r in available:
            print(f"  {_label(r)}")
    if unavailable:
        print(f"\n--- 不可用账号 ({_avail_reason}) ({len(unavailable)}) ---")
        for r in unavailable:
            print(f"  {_label(r)}")
    if bad:
        print(f"\n--- 失败账号 ({len(bad)}) ---")
        for r in bad:
            print(f"  {_label(r)}  ({r.get('error')})")
    print("=" * 60)

    # 可用账号已在查询过程中实时写入 out_available（见 _write_available），这里只汇总。
    if written:
        print(f"\n✅ 已实时写入 {len(written)} 个可用账号（含配额结果）→ {out_available}")
    else:
        print("\n（无可用账号，未写文件）")
    return


# aws 模式：批量登录 AWS Root（仅登录，落 console 首页；后续流程见 aws-claude / aws-kiro）
async def run_aws_batch(mode: str, raw_input: str, is_file: bool):
    lines = read_aws_records(raw_input, is_file)
    logger.info(f"读取到 {len(lines)} 个 AWS 账号，开始批量登录...")

    results = []
    # AWS 登录页/控制台元素较多，窗口铺满屏幕 + 视口随窗口自适应
    async with cloak_browser_session(maximized=True) as browser:
        try:
            for idx, line in enumerate(lines, 1):
                try:
                    email, password, totp_secret, akid, sak, _region = parse_aws_input(line)
                except ValueError as e:
                    logger.warning(f"[{idx}/{len(lines)}] 解析失败: {e}")
                    results.append({"email": line[:30], "status": "解析失败"})
                    continue

                logger.info(f"[{idx}/{len(lines)}] 登录 AWS: {email}")
                context = await new_window_sized_context(browser, storage_state=_ctx_state_path(email))
                try:
                    final_url = await login_aws(context, email, password, totp_secret, akid, sak)
                    logger.info(f"[{idx}/{len(lines)}] {email}: 成功 -> {final_url}")
                    if _session_reuse_enabled():
                        await save_aws_session(context, email)
                    results.append({"email": email, "status": "成功", "url": final_url})
                except Exception as e:
                    logger.warning(f"[{idx}/{len(lines)}] {email}: 失败 - {e}")
                    results.append({"email": email, "status": f"失败: {e}"})
                finally:
                    await context.close()
        finally:
            print("\n" + "=" * 60)
            print("批量 AWS 登录结果汇总")
            print("=" * 60)
            success = [r for r in results if r["status"] == "成功"]
            failed = [r for r in results if r["status"] != "成功"]
            print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
            if failed:
                print(f"\n--- 失败账号 ({len(failed)}) ---")
                for r in failed:
                    print(f"  {r['email']}  ({r['status']})")
            print("=" * 60)
    return


# aws-claude 模式：登录 AWS → Claude Platform access 开通访问 → 生成长期 key → 抓 workspace_id。
# 产出追加到 aws_api_keys.txt（email----api_key----workspace_id），可喂给 `subus` 模式推送。
async def run_aws_claude(mode: str, raw_input: str, is_file: bool):
    lines = read_aws_records(raw_input, is_file)
    if not lines:
        print("无可处理的账号行")
        exit(1)
    logger.info(f"读取到 {len(lines)} 个 AWS 账号，开始登录并开通 Claude Platform...")

    results = []
    async with cloak_browser_session(maximized=True) as browser:
        try:
            for idx, line in enumerate(lines, 1):
                try:
                    email, password, totp_secret, akid, sak, _region = parse_aws_input(line)
                except ValueError as e:
                    logger.warning(f"[{idx}/{len(lines)}] 解析失败: {e}")
                    results.append({"email": line[:30], "status": "解析失败"})
                    continue

                logger.info(f"[{idx}/{len(lines)}] 登录 AWS + Claude Platform: {email}")
                context = await new_window_sized_context(browser, storage_state=_ctx_state_path(email))
                try:
                    final_url = await login_aws_claude(context, email, password, totp_secret, akid, sak)
                    logger.info(f"[{idx}/{len(lines)}] {email}: 成功 -> {final_url}")
                    if _session_reuse_enabled():
                        await save_aws_session(context, email)
                    results.append({"email": email, "status": "成功", "url": final_url})
                except Exception as e:
                    logger.warning(f"[{idx}/{len(lines)}] {email}: 失败 - {e}")
                    results.append({"email": email, "status": f"失败: {e}"})
                finally:
                    await context.close()
        finally:
            print("\n" + "=" * 60)
            print("aws-claude 开通结果汇总")
            print("=" * 60)
            success = [r for r in results if r["status"] == "成功"]
            failed = [r for r in results if r["status"] != "成功"]
            print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
            if success:
                print(f"\nkey/workspace_id 已追加到 {AWS_OUTPUT_FILE}"
                      f"（用 `python main.py subus {AWS_OUTPUT_FILE}` 推送）")
            if failed:
                print(f"\n--- 失败账号 ({len(failed)}) ---")
                for r in failed:
                    print(f"  {r['email']}  ({r['status']})")
            print("=" * 60)
    return


def _kiro_arg_val(extra: list, name: str, default=None):
    """从命令行额外参数取 `--name <value>`，缺省返回 default。"""
    if name in extra:
        i = extra.index(name)
        if i + 1 < len(extra):
            return extra[i + 1]
    return default


def _derive_username_base(email: str) -> str:
    """从 admin 登录邮箱推出随机用户名的基名：取 @ 前的本地部分，去掉非字母数字字符。
    例 admin 是 `kiro.user+1@x.com` → base=`kirouser1`，再由随机后缀拼成 kirouser18f3ka9x2…
    （这里只产基名，随机后缀在 _gen_random_usernames 里拼）。空则回退 'kiro'。"""
    local = (email or "").split("@", 1)[0]
    base = re.sub(r"[^A-Za-z0-9]", "", local)
    return base or "kiro"


# 随机用户名后缀长度：8 位小写字母+数字 ≈ 36^8 ≈ 2.8e12 空间，count 级别撞名概率可忽略。
_RANDOM_SUFFIX_LEN = 8


def _gen_random_usernames(base: str, count: int) -> list:
    """默认命名：基名 + 一段随机小写字母数字后缀（如 kiro8f3ka9x2），非顺序、不可枚举。
    足够熵避免撞名，且本批内去重；替代旧的持久化顺序号命名。"""
    pool = string.ascii_lowercase + string.digits
    names, seen = [], set()
    while len(names) < count:
        suffix = "".join(secrets.choice(pool) for _ in range(_RANDOM_SUFFIX_LEN))
        name = f"{base}{suffix}"
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


# aws-kiro 模式：登录 AWS（admin）→ IAM Identity Center 自动建用户（抓一次性密码）。
def _summarize_aws_kiro(results: list, out_path: str) -> None:
    """打印 aws-kiro 建用户结果汇总（API/浏览器两条路径共用）。"""
    print("\n" + "=" * 60)
    print("aws-kiro 建用户结果汇总")
    print("=" * 60)
    success = [r for r in results if str(r.get("status", "")).startswith("成功")]
    others = [r for r in results if not str(r.get("status", "")).startswith("成功")]
    print(f"\n总计: {len(results)}  成功: {len(success)}  其它: {len(others)}")
    done = [r for r in results if r.get("username")]
    if done:
        print(f"\n--- 已建用户 ({len(done)}) ---")
        for r in done:
            grp = r.get("group")
            print(f"  {r.get('username')}  otp={'有' if r.get('one_time_password') else '无'}"
                  f"  portal={r.get('start_url') or '未抓到'}"
                  + (f"  group={grp}" if grp else ""))
    if any(r.get("idc_line") for r in results):
        print(f"\n可消费记录已追加到 {out_path}（用 `python main.py kiro {out_path}` 登录）")
        print(f"整段登录信息原文见 {out_path}.full.txt")
    if others:
        print(f"\n--- 需关注 ({len(others)}) ---")
        for r in others:
            print(f"  {r.get('admin')}  ({r.get('status')})")
    print("=" * 60)


async def _run_aws_kiro_api(
    lines: list, count: int, custom_usernames: list, username_base_cli: str,
    region_cli: str, email_domain: str, group_name: str, out_path: str,
) -> None:
    """纯 API 建用户（--ak/--api 显式开启）。每个 admin 行需含 AK/SK；无浏览器、无 WAF。

    命名/序号/加组逻辑与浏览器路径一致，产出同样的 idc:: 行与 .full.txt。
    """
    results = []
    for idx, line in enumerate(lines, 1):
        try:
            email, _password, _totp, akid, sak, line_region = parse_aws_input(line)
        except ValueError as e:
            logger.warning(f"[{idx}/{len(lines)}] admin 解析失败: {e}")
            results.append({"admin": line[:30], "status": f"解析失败: {e}"})
            continue
        if not (akid and sak):
            msg = "--ak/--api 纯 API 模式需要 AK/SK（输入行含 access_key_id/secret_access_key），去掉 --ak 即走默认浏览器"
            logger.warning(f"[{idx}/{len(lines)}] admin={email or line[:30]}: {msg}")
            results.append({"admin": email or line[:30], "status": msg})
            continue

        eff_region = region_cli or AWS_IDC_REGION or line_region
        inst = await asyncio.to_thread(idc_list_instance, akid, sak, eff_region)
        if inst.get("error"):
            logger.warning(f"[{idx}/{len(lines)}] admin={email} 探实例失败: {inst['error']}")
            results.append({"admin": email, "status": f"探实例失败: {inst['error']}"})
            continue
        identity_store_id = inst["identity_store_id"]
        start_url = idc_portal_url(identity_store_id)

        base = username_base_cli or _derive_username_base(email)
        if custom_usernames:
            user_names = list(custom_usernames)
        else:
            user_names = _gen_random_usernames(base, count)

        # 组 id 每个 admin 只查/建一次：组不存在则自动创建
        group_id = ""
        if group_name:
            fc = await asyncio.to_thread(
                idc_find_or_create_group, akid, sak, eff_region, identity_store_id, group_name)
            group_id = fc.get("group_id") or ""
            if fc.get("error"):
                logger.warning(f"[{idx}/{len(lines)}] 查/建组 {group_name!r} 失败，将不加组: {fc['error']}")
            elif fc.get("created"):
                logger.info(f"[{idx}/{len(lines)}] 组 {group_name!r} 不存在，已自动创建 GroupId={group_id}")

        for j, seq_username in enumerate(user_names, 1):
            logger.info(f"[{idx}/{len(lines)}] admin={email} 第 {j}/{len(user_names)} 个用户"
                        f" {seq_username}（region={eff_region}, API）...")
            try:
                r = await asyncio.to_thread(
                    provision_idc_user_api, akid, sak, eff_region, identity_store_id,
                    start_url, email_domain, base, group_name, seq_username, group_id,
                )
            except Exception as e:
                logger.warning(f"[{idx}/{len(lines)}] admin={email} 第 {j} 个用户异常: {e}")
                results.append({"admin": email, "status": f"第{j}个用户异常: {e}"})
                continue
            if r.get("error"):
                logger.warning(f"[{idx}/{len(lines)}] {seq_username} 失败: {r['error']}")
                results.append({"admin": email, "status": f"失败: {r['error']}"})
                continue
            with open(out_path, "a") as f:
                f.write(r["idc_line"] + "\n")
            with open(out_path + ".full.txt", "a") as f:
                f.write(f"# {r['username']} ({email})\n{r['login_info']}\n\n")
            r["admin"] = email
            r["status"] = "成功"
            logger.info(f"[{idx}/{len(lines)}] {r['username']}: 成功")
            results.append(r)
    _summarize_aws_kiro(results, out_path)


async def _run_aws_kiro_selenium(lines, count, custom_usernames, username_base_cli,
                                 region_cli, email_domain, group_name, out_path,
                                 instance_id, backend):
    """aws-kiro 的 Selenium 版（backend=chrome/safari，过 AWS WAF）。每个 admin 一个浏览器：
    登录一次 → 建 count 个 IDC 用户。Selenium 同步调用用 asyncio.to_thread 包，不阻塞事件循环。
    行为对齐 Playwright 分支（用户名生成/落盘/汇总一致）；差异：无 storage_state 会话复用，
    每个 admin 现登现建（Selenium 真浏览器过 WAF，重登成本可接受）。"""
    from app.accounts.aws_idc_selenium import (
        open_console_and_prepare, provision_idc_user, close_driver)
    results = []
    try:
        for idx, line in enumerate(lines, 1):
            try:
                email, password, totp_secret, akid, sak, line_region = parse_aws_input(line)
            except ValueError as e:
                logger.warning(f"[{idx}/{len(lines)}] admin 解析失败: {e}")
                results.append({"admin": line[:30], "status": f"解析失败: {e}"})
                continue
            eff_region = region_cli or AWS_IDC_REGION or line_region
            base = username_base_cli or _derive_username_base(email)
            user_names = (list(custom_usernames) if custom_usernames
                          else _gen_random_usernames(base, count))

            try:
                driver, rid, start_url = await asyncio.to_thread(
                    open_console_and_prepare, email, password, totp_secret,
                    akid, sak, eff_region, instance_id, backend)
            except Exception as e:
                logger.warning(f"[{idx}/{len(lines)}] admin={email} 登录失败: {e}")
                results.append({"admin": email, "status": f"登录失败: {e}"})
                continue
            try:
                for j, seq_username in enumerate(user_names, 1):
                    logger.info(f"[{idx}/{len(lines)}] admin={email} 第 {j}/{count} 个用户"
                                f" {seq_username}（region={eff_region}, backend={backend}）...")
                    try:
                        r = await asyncio.to_thread(
                            provision_idc_user, driver, email, eff_region, rid, start_url,
                            email_domain, base, group_name, seq_username)
                        r["admin"] = email
                        if r.get("idc_line"):
                            with open(out_path, "a") as f:
                                f.write(r["idc_line"] + "\n")
                        if r.get("login_info"):
                            with open(out_path + ".full.txt", "a") as f:
                                f.write(f"# {r['username']} ({email})\n{r['login_info']}\n\n")
                        ok = bool(r.get("one_time_password"))
                        r["status"] = "成功" if ok else "部分成功(未抓到登录信息)"
                        logger.info(f"[{idx}/{len(lines)}] {r['username']}: {r['status']}")
                        results.append(r)
                    except Exception as e:
                        logger.warning(f"[{idx}/{len(lines)}] admin={email} 第 {j} 个用户失败: {e}")
                        results.append({"admin": email, "status": f"第{j}个用户失败: {e}"})
            finally:
                await asyncio.to_thread(close_driver, driver)
    finally:
        _summarize_aws_kiro(results, out_path)


# 产出可直接喂给 `kiro` 模式的 idc:: 行。
async def run_aws_kiro(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    # --backend chrome/safari/camoufox/… 覆盖浏览器后端（chrome/safari 走 Selenium 过 WAF）。
    # 注意：aws-kiro 的 --browser 是「走浏览器路径」的意思，不是后端值，故这里只认 --backend。
    _be = _kiro_arg_val(extra, "--backend", None)
    if _be:
        os.environ["KIRO_BROWSER_BACKEND"] = _be.strip()
        logger.info(f"命令行覆盖浏览器后端：KIRO_BROWSER_BACKEND={_be.strip()}")
    try:
        count = int(_kiro_arg_val(extra, "--count", "1"))
    except ValueError:
        print("--count 需要一个整数")
        exit(1)
    # 完全自定义用户名：--username a 或 --username a,b,c（逗号分隔），按原样使用、不拼序号。
    # 不传 --username 时回退 config 的 AWS_IDC_USERNAME（字符串逗号分隔或列表）。
    # 只指定用户名不传 --count 时，count 自动取名字个数；
    # 「单个名字 + --count N>1」则把该名字当基名按序号扩展（等效 --username-prefix）。
    # 多个 admin 行时，每个 admin 都用这组名字建用户（各 admin 是独立 IDC 实例，不会撞名）。
    username_cli = _kiro_arg_val(extra, "--username", None)
    if username_cli is None:
        username_cfg = AWS_IDC_USERNAME
        username_cli = (",".join(username_cfg) if isinstance(username_cfg, (list, tuple))
                        else (username_cfg or None))
    custom_usernames = ([u.strip() for u in username_cli.split(",") if u.strip()]
                        if username_cli else [])
    if username_cli and not custom_usernames:
        print("--username / AWS_IDC_USERNAME 需要至少一个非空用户名（多个用逗号分隔）")
        exit(1)
    username_as_base = None  # 单个自定义名 + count>1 时，转为「基名+序号」命名
    if custom_usernames:
        if "--count" not in extra:
            count = len(custom_usernames)
        elif count != len(custom_usernames):
            if len(custom_usernames) == 1:
                username_as_base = custom_usernames[0]
                custom_usernames = []
            else:
                print(f"--username 给了 {len(custom_usernames)} 个名字，与 --count {count} 不一致；"
                      f"要「基名+序号」批量命名请只给一个名字或改用 --username-prefix")
                exit(1)
    # 区域优先级（IAM Identity Center 用它）：
    #   --region 显式传入 > config 的 AWS_IDC_REGION（默认 us-east-1）> 输入行自带 region。
    # 注意：输入行的 region 是「账号控制台区域」，与 Identity Center 实例所在区域是两码事，
    # 之前让它覆盖会把 SSO 带到 eu-north-1。现在固定走 config，避免跳区。
    region_cli = _kiro_arg_val(extra, "--region", "")
    instance_id = _kiro_arg_val(extra, "--instance-id", AWS_IDC_INSTANCE_ID)
    email_domain = _kiro_arg_val(extra, "--email-domain", AWS_IDC_EMAIL_DOMAIN)
    # 随机命名基名：默认用 admin 登录账号名（邮箱前缀），显式传 --username-prefix 则用其作自定义基名；
    # 「--username/AWS_IDC_USERNAME 单个名字 + --count N」也落到这里当基名
    username_base_cli = _kiro_arg_val(extra, "--username-prefix", None) or username_as_base
    group_name = _kiro_arg_val(extra, "--group", AWS_IDC_GROUP)
    out_path = _kiro_arg_val(extra, "--out", AWS_IDC_KIRO_OUTPUT_FILE)

    lines = read_aws_records(raw_input, is_file)
    if not lines:
        print("无可处理的 admin 账号行")
        exit(1)

    # 默认【优先网页（浏览器）建用户】；仅当显式 --ak/--api 时走纯 API（需 AK/SK）。
    # 兼容旧参数：--browser 仍表示走浏览器（现在本就是默认），与 --ak 冲突时 --browser 优先。
    if "--browser" in extra:
        use_ak = False
    else:
        use_ak = ("--ak" in extra) or ("--api" in extra)
    logger.info(
        f"读取到 {len(lines)} 个 admin 账号，每个建 {count} 个 IDC 用户"
        f"（region={region_cli or AWS_IDC_REGION}(固定，不随输入行), "
        f"instance_id={instance_id or '自动探测'}, "
        f"group={group_name or '(不加组)'}, "
        f"命名={'指定用户名 ' + '/'.join(custom_usernames) if custom_usernames else (('自定义 ' + username_base_cli if username_base_cli else 'admin账号名') + '+随机后缀')}, "
        f"流程={'API建用户(--ak/--api)' if use_ak else '浏览器建用户(默认)'}）"
    )

    # 仅 --ak/--api 显式指定时走纯 API（无浏览器/WAF，需 AK/SK）；否则默认走浏览器点击流。
    if use_ak:
        await _run_aws_kiro_api(
            lines, count, custom_usernames, username_base_cli,
            region_cli, email_domain, group_name, out_path,
        )
        return

    # backend=chrome/safari → 走 Selenium 真浏览器（过 AWS WAF），而非 Playwright camoufox。
    _wd_backend = kiro_browser_backend()
    if _wd_backend in ("chrome", "safari"):
        await _run_aws_kiro_selenium(
            lines, count, custom_usernames, username_base_cli, region_cli,
            email_domain, group_name, out_path, instance_id, _wd_backend)
        return

    results = []
    async with cloak_browser_session(maximized=True) as browser:
        try:
            for idx, line in enumerate(lines, 1):
                try:
                    email, password, totp_secret, akid, sak, line_region = parse_aws_input(line)
                except ValueError as e:
                    logger.warning(f"[{idx}/{len(lines)}] admin 解析失败: {e}")
                    results.append({"admin": line[:30], "status": f"解析失败: {e}"})
                    continue

                # config 区域优先于输入行 region，固定走 us-east-1（不再被行内 Stockholm 等带偏）
                eff_region = region_cli or AWS_IDC_REGION or line_region

                # 用户名：--username 指定则原样使用；
                # 否则随机命名：基名 = 自定义(--username-prefix) 或 admin 登录账号名，拼随机后缀
                base = username_base_cli or _derive_username_base(email)
                if custom_usernames:
                    user_names = list(custom_usernames)
                else:
                    user_names = _gen_random_usernames(base, count)

                # 每个 admin 只登录一次：建 1 个 context、登录落到 IDC，后续 count 个用户
                # 全部复用同一 page（--count 不再每次重新登录）。
                # 复用已保存会话（默认开启，--no-session 关闭），跨次运行跳过 root 登录。
                context = await new_window_sized_context(browser, storage_state=_ctx_state_path(email))
                try:
                    try:
                        page, resolved_instance_id, start_url = await aws_idc_open_console(
                            context, email, password, totp_secret, akid, sak,
                            eff_region, instance_id,
                        )
                        if _session_reuse_enabled():
                            await save_aws_session(context, email)
                    except Exception as e:
                        logger.warning(f"[{idx}/{len(lines)}] admin={email} 登录失败: {e}")
                        results.append({"admin": email, "status": f"登录失败: {e}"})
                        continue  # finally 会关掉 context，再换下一个 admin

                    for j, seq_username in enumerate(user_names, 1):
                        # seq_username：--username 原样指定，或 基名+随机后缀（foo8f3ka9x2…）
                        logger.info(f"[{idx}/{len(lines)}] admin={email} 第 {j}/{count} 个用户"
                                    f" {seq_username}（region={eff_region}）...")
                        try:
                            r = await provision_idc_user_on_page(
                                page, email, eff_region, resolved_instance_id, start_url,
                                email_domain, base, group_name,
                                username=seq_username,
                            )
                            r["admin"] = email
                            if r.get("idc_line"):
                                with open(out_path, "a") as f:
                                    f.write(r["idc_line"] + "\n")
                            # 整段登录信息原文也落盘保存（portal URL + 用户名 + 一次性密码全保留）
                            if r.get("login_info"):
                                raw_path = out_path + ".full.txt"
                                with open(raw_path, "a") as f:
                                    f.write(f"# {r['username']} ({email})\n{r['login_info']}\n\n")
                            ok = bool(r.get("one_time_password"))
                            r["status"] = "成功" if ok else "部分成功(未抓到登录信息)"
                            logger.info(f"[{idx}/{len(lines)}] {r['username']}: {r['status']}")
                            results.append(r)
                        except Exception as e:
                            # 单个用户失败不影响同一 admin 的后续用户
                            logger.warning(f"[{idx}/{len(lines)}] admin={email} 第 {j} 个用户失败: {e}")
                            results.append({"admin": email, "status": f"第{j}个用户失败: {e}"})
                finally:
                    await context.close()
        finally:
            _summarize_aws_kiro(results, out_path)
    return


# ── aws-kiro-bind：用 admin AK/SK 把该账号下所有 IDC 用户批量绑定 Kiro 订阅 ────────
def _summarize_kiro_bind(results: list, dry_run: bool, power: bool = False) -> None:
    """打印 aws-kiro-bind 结果汇总（sso-admin 绑定 / --power 开付费订阅共用）。"""
    tag = "（DRY-RUN，未写入）" if dry_run else ""
    verb = "将开通" if dry_run else "新开通"
    title = "开通 Kiro 付费订阅(q:CreateAssignment)" if power else "绑定 Kiro 订阅(sso-admin)"
    print("\n" + "=" * 60)
    print(f"aws-kiro-bind {title}结果{tag}")
    print("=" * 60)
    ok = [r for r in results if str(r.get("status", "")).startswith("成功")]
    tot_assigned = sum(r.get("assigned", 0) for r in results)
    tot_already = sum(r.get("already", 0) for r in results)
    tot_failed = sum(r.get("failed", 0) for r in results)
    line = (f"\n账号总计: {len(results)}  成功: {len(ok)}  "
            f"{verb}: {tot_assigned}")
    if tot_already:
        line += f"  已订阅: {tot_already}"
    line += f"  失败: {tot_failed}"
    print(line)
    for r in results:
        scope = "/".join(r.get("apps") or [])
        head = f"  {r.get('admin')}: {r.get('status')}"
        if r.get("assigned") is not None and r.get("status", "").startswith(("成功", "部分")):
            head += f"  [{scope}] {verb}{r.get('assigned', 0)}"
            if r.get("already"):
                head += f" 已订阅{r.get('already')}"
            if r.get("failed"):
                head += f" 失败{r.get('failed')}"
        print(head)
        for e in r.get("errs") or []:
            print(f"      ! {e}")
    print("=" * 60)


def _bind_kiro_one_admin(line: str, region_cli: str, group_name: str, dry_run: bool,
                         idx: int, total: int) -> dict:
    """单个 admin 账号 sso-admin 应用绑定，支持**个人/分组**两种范式：
      - 分组（传 --group <名>）：对该组发**一条** GROUP assign/应用（组内全员继承，最省）；
      - 个人（不传 --group）：拉全部 IDC 用户，逐个 USER assign。
    同步函数（含多次 HTTP），由 run_aws_kiro_bind 用 asyncio.to_thread 调用。"""
    try:
        email, _pw, _totp, akid, sak, line_region = parse_aws_input(line)
    except ValueError as e:
        logger.warning(f"[{idx}/{total}] admin 解析失败: {e}")
        return {"admin": line[:30], "status": f"解析失败: {e}"}
    if not (akid and sak):
        return {"admin": email or line[:30], "status": "缺 AK/SK（本模式需 admin AK/SK）"}
    # 输入行没带邮箱（如裸 `AK SK`）时用 AK 尾 6 位当标签，避免汇总里空白
    admin = email or f"…{akid[-6:]}"

    eff_region = region_cli or AWS_IDC_REGION or line_region
    inst = idc_list_instance(akid, sak, eff_region)
    if inst.get("error"):
        logger.warning(f"[{idx}/{total}] admin={admin} 探实例失败: {inst['error']}")
        return {"admin": admin, "status": f"探实例失败: {inst['error']}"}

    appr = idc_list_kiro_profile_apps(akid, sak, eff_region, inst["instance_arn"])
    if appr.get("error") and not appr.get("apps"):
        return {"admin": admin, "status": f"列应用失败: {appr['error']}"}
    apps = appr["apps"]
    if not apps:
        return {"admin": admin, "status": "未找到 KiroProfile 订阅应用（该号未开 Kiro?）"}

    # 目标 principal 列表：分组=一条 GROUP；个人=逐用户 USER
    if group_name:
        gid = idc_find_group_id(akid, sak, eff_region, inst["identity_store_id"], group_name)
        if not gid:
            return {"admin": admin, "status": f"未找到组 {group_name}"}
        targets = [(gid, "GROUP", f"group:{group_name}")]
        scope_label = f"组[{group_name}]"
    else:
        usr = idc_list_users(akid, sak, eff_region, inst["identity_store_id"])
        if usr.get("error") and not usr.get("users"):
            return {"admin": admin, "status": f"列用户失败: {usr['error']}"}
        users = usr["users"]
        if not users:
            return {"admin": admin, "status": "该号无 IDC 用户", "users": 0,
                    "apps": [a["name"] for a in apps], "assigned": 0, "failed": 0}
        targets = [(u["user_id"], "USER", u["user_name"]) for u in users]
        scope_label = f"{len(users)}用户"

    assigned = failed = 0
    errs: list = []
    ntotal = len(targets) * len(apps)
    if not dry_run:
        logger.info(f"[{idx}/{total}] admin={admin} 开始绑定（{scope_label}）：{len(targets)} principal × "
                    f"{len(apps)} 应用 = {ntotal} 个 assign（串行，请耐心）")
    done = 0
    for pid, ptype, plabel in targets:
        for app in apps:
            if dry_run:
                assigned += 1
                continue
            ar = idc_create_application_assignment(
                akid, sak, eff_region, app["arn"], pid, ptype)
            if ar.get("error"):
                failed += 1
                if len(errs) < 3:
                    errs.append(f"{plabel}→{app['name']}: {ar['error']}")
            else:
                assigned += 1
            done += 1
            if done % 20 == 0 or done == ntotal:
                logger.info(f"[{idx}/{total}] admin={admin} 进度 {done}/{ntotal} "
                            f"（成功={assigned} 失败={failed}）")
    status = "成功" if failed == 0 else f"部分失败({failed})"
    logger.info(f"[{idx}/{total}] admin={admin} {scope_label} 应用={len(apps)} "
                f"{'将绑' if dry_run else '绑定'}={assigned} 失败={failed}")
    return {"admin": admin, "status": status, "users": len(targets),
            "apps": [scope_label] + [a["name"] for a in apps], "assigned": assigned,
            "failed": failed, "errs": errs}


def _bind_power_one_admin(line: str, region_cli: str, tier: str, profile_arn_cli: str,
                          access_token_cli: str, group_name: str, dry_run: bool,
                          idx: int, total: int) -> dict:
    """--power 路径：用 q:CreateAssignment 给该号开付费订阅（默认 POWER，真实计费）。

    profileArn 来源：--profile-arn 显式给，或由 --access-token 经 kiro_list_first_profile_arn 派生。
    --group 时对整组发**一条** GROUP 请求（组内全员开通）；否则逐用户 USER 请求。
    仅「标准 IdC 实例」账号可 AK 直调；企业/org 实例会 AccessDenied（需回退 sso-admin，不带 --power）。
    """
    try:
        email, _pw, _totp, akid, sak, line_region = parse_aws_input(line)
    except ValueError as e:
        return {"admin": line[:30], "status": f"解析失败: {e}"}
    if not (akid and sak):
        return {"admin": email or line[:30], "status": "缺 AK/SK"}
    admin = email or f"…{akid[-6:]}"
    eff_region = region_cli or AWS_IDC_REGION or line_region

    profile_arn = profile_arn_cli
    if not profile_arn and access_token_cli:
        profile_arn = kiro_list_first_profile_arn(access_token_cli, eff_region)
    if not profile_arn:
        return {"admin": admin, "status": "缺 profileArn（--power 需 --profile-arn 或 --access-token）"}

    inst = idc_list_instance(akid, sak, eff_region)
    if inst.get("error"):
        return {"admin": admin, "status": f"探实例失败: {inst['error']}"}

    tier_short = tier.replace("Q_DEVELOPER_STANDALONE_", "")
    # 目标：--group 一条覆盖整组；否则逐用户
    if group_name:
        gid = idc_find_group_id(akid, sak, eff_region, inst["identity_store_id"], group_name)
        if not gid:
            return {"admin": admin, "status": f"未找到组 {group_name}"}
        targets = [(gid, "GROUP", f"group:{group_name}")]
        scope = [tier_short, f"GROUP:{group_name}"]
    else:
        usr = idc_list_users(akid, sak, eff_region, inst["identity_store_id"])
        if usr.get("error") and not usr.get("users"):
            return {"admin": admin, "status": f"列用户失败: {usr['error']}"}
        targets = [(u["user_id"], "USER", u["user_name"]) for u in usr["users"]]
        scope = [tier_short, f"{len(targets)}用户"]
        if not targets:
            return {"admin": admin, "status": "该号无 IDC 用户",
                    "apps": scope, "assigned": 0, "already": 0, "failed": 0}

    assigned = already = failed = 0
    errs: list = []
    for pid, ptype, label in targets:
        if dry_run:
            assigned += 1
            continue
        r = q_create_assignment(akid, sak, eff_region, profile_arn, pid, ptype, tier)
        if r.get("error"):
            failed += 1
            if len(errs) < 3:
                errs.append(f"{label}: {r['error']}")
        elif r.get("already"):
            already += 1
        else:
            assigned += 1
    status = "成功" if failed == 0 else f"部分失败({failed})"
    logger.info(f"[{idx}/{total}] admin={admin} {'/'.join(scope)} tier={tier} "
                f"{'将开' if dry_run else '新开'}={assigned} 已订阅={already} 失败={failed}")
    return {"admin": admin, "status": status, "apps": scope,
            "assigned": assigned, "already": already, "failed": failed, "errs": errs}


async def run_aws_kiro_bind(mode: str, raw_input: str, is_file: bool):
    """把 admin 账号（AK/SK）下的 IDC 用户批量绑定/开通 Kiro 订阅。

    输入格式与 aws-kiro 一致（parse_aws_input，需含 AK/SK）；单条或文件均可。
    参数：
      --region <r>    默认 config AWS_IDC_REGION（固定不随输入行）
      --dry-run       只统计不写入
      --power         开**付费订阅**（q:CreateAssignment，真实计费）；不带则只做 sso-admin 应用绑定
      --tier <T>      配合 --power 指定档位（默认 Q_DEVELOPER_STANDALONE_POWER）
      --profile-arn <arn> / --access-token <aoa...>   --power 取 profileArn（后者自动派生）
      --group <name>  **分组范式**：对该组发**一条** GROUP 请求（组内全员继承，批量最优）；
                      不传则**个人范式**逐用户 assign。sso-admin 绑定与 --power 均支持。
    """
    extra = sys.argv[3:]
    region_cli = _kiro_arg_val(extra, "--region", "")
    dry_run = "--dry-run" in extra
    power = "--power" in extra
    tier = _kiro_arg_val(extra, "--tier", KIRO_SUBSCRIPTION_DEFAULT)
    profile_arn_cli = _kiro_arg_val(extra, "--profile-arn", "")
    access_token_cli = _kiro_arg_val(extra, "--access-token", "")
    group_name = _kiro_arg_val(extra, "--group", "")

    lines = read_aws_records(raw_input, is_file)
    if not lines:
        print("无可处理的 admin 账号行")
        exit(1)

    if power and not (profile_arn_cli or access_token_cli):
        print("--power 需要 --profile-arn <arn> 或 --access-token <aoa...> 以取 profileArn")
        exit(1)

    scope_desc = f"组[{group_name}]一次覆盖" if group_name else "逐用户"
    mode_desc = (f"开付费订阅 --power tier={tier} {scope_desc}") if power \
        else f"sso-admin 应用绑定 {scope_desc}"
    logger.info(f"aws-kiro-bind：读取到 {len(lines)} 个 admin 账号，"
                f"region={region_cli or AWS_IDC_REGION}(固定)，{mode_desc}，"
                f"{'DRY-RUN(仅统计，不写入)' if dry_run else '写入'}")

    results = []
    for idx, line in enumerate(lines, 1):
        if power:
            r = await asyncio.to_thread(
                _bind_power_one_admin, line, region_cli, tier, profile_arn_cli,
                access_token_cli, group_name, dry_run, idx, len(lines))
        else:
            r = await asyncio.to_thread(
                _bind_kiro_one_admin, line, region_cli, group_name, dry_run, idx, len(lines))
        results.append(r)
    _summarize_kiro_bind(results, dry_run, power=power)


# aws-newapi 模式：把 AWS AK/SK 注册成 New API 后台的 AWS Bedrock 渠道（type=33，纯 HTTP，不开浏览器）
async def run_aws_newapi(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]

    # --regions us-west-2,us-east-1  覆盖默认区域（默认取 config NEWAPI_REGIONS）
    regions = list(NEWAPI_REGIONS)
    regions_cli = _kiro_arg_val(extra, "--regions", None)
    if regions_cli is not None:
        regions = [r.strip() for r in regions_cli.split(",") if r.strip()]

    group = _kiro_arg_val(extra, "--group", NEWAPI_DEFAULT_GROUP)
    prefix = _kiro_arg_val(extra, "--prefix", NEWAPI_NAME_PREFIX)
    dry_run = "--dry-run" in extra

    # 默认每个账号末尾追加一条 global 渠道（global. 前缀，全球路由）；--no-global 跳过。
    # --global-region <region> 覆盖 global 渠道的 source region（默认 NEWAPI_GLOBAL_SOURCE_REGION）。
    skip_global = "--no-global" in extra
    global_region = _kiro_arg_val(extra, "--global-region", NEWAPI_GLOBAL_SOURCE_REGION) \
        or NEWAPI_GLOBAL_SOURCE_REGION
    global_map = newapi_model_mapping_for_geo("global")
    if not skip_global and not global_map:
        logger.warning("global 模型映射为空（NEWAPI_MODEL_MAPPING_BY_GEO 无 'global'），不追加 global 渠道")
        skip_global = True

    lines = read_aws_records(raw_input, is_file)
    if not lines:
        print("无可处理的账号行")
        exit(1)
    if not regions:
        print("无可用区域（配置 NEWAPI_REGIONS 或传 --regions）")
        exit(1)

    # 先解析出所有 (email, ak, sk)，跳过缺 AK/SK 的行
    accounts = []
    for idx, line in enumerate(lines, 1):
        try:
            email, _pwd, _totp, ak, sk, _region = parse_aws_input(line)
        except ValueError as e:
            logger.warning(f"[{idx}/{len(lines)}] 解析失败: {e}")
            continue
        if not ak or not sk:
            logger.warning(f"[{idx}/{len(lines)}] {email or line[:40]}: 缺 AK/SK，跳过")
            continue
        accounts.append((email, ak, sk))

    if not accounts:
        print("无带 AK/SK 的账号可推送")
        exit(0)

    batch_ts = time.strftime("%Y%m%d%H%M%S")
    per_account = len(regions) + (0 if skip_global else 1)
    total = len(accounts) * per_account
    logger.info(f"aws-newapi：准备把 {len(accounts)} 个账号 × {per_account} 条 "
                f"({len(regions)} 区域{'' if skip_global else f' + 1 global@{global_region}'}) = {total} 条渠道 "
                f"推到 New API 后台（group={group}，批次 ts={batch_ts}，"
                f"{'DRY-RUN(仅列出，不写入)' if dry_run else '写入'}）")

    def _label(email: str, ak: str) -> str:
        """渠道名里的账号标识：有 email 用邮箱前缀，没 email 用 AK 尾 4 位（纯 AK/SK 批量也能区分）。"""
        local = re.sub(r"[^A-Za-z0-9]", "", (email or "").split("@", 1)[0])
        return local or (ak[-4:] if ak else "aws")

    results = []
    idx = 0
    for email, ak, sk in accounts:
        acct_label = _label(email, ak)
        # 每个 region 一条 + 末尾可选一条 global。用 (region, geo, name_tag, mapping) 统一驱动。
        jobs = [(region, aws_region_to_geo(region), region, None) for region in regions]
        if not skip_global:
            jobs.append((global_region, "global", "global", global_map))
        for region, geo, name_tag, forced_map in jobs:
            idx += 1
            name = f"{prefix}-{acct_label}-{name_tag}-{batch_ts}"
            mapping = forced_map if forced_map is not None else newapi_model_mapping_for_region(region)
            if dry_run:
                tag = "" if mapping else "  [跳过: geo 无模型映射]"
                logger.info(f"[{idx}/{total}] DRY-RUN {name}  region={region}  geo={geo}  ak={ak[:8]}...{tag}")
                results.append({"name": name, "region": region, "geo": geo,
                                "status": "dry-run" if mapping else "跳过"})
                continue
            logger.info(f"[{idx}/{total}] {name}  region={region}  geo={geo}  ak={ak[:8]}...")
            ok = await asyncio.to_thread(
                register_newapi_channel, ak, sk, region, name, "", "", "",
                group, None, mapping)
            results.append({"name": name, "region": region, "geo": geo,
                            "status": "成功" if ok else "失败"})

    print("\n" + "=" * 60)
    print(f"New API 建渠道结果汇总  批次 ts={batch_ts}")
    print("=" * 60)
    if dry_run:
        print(f"\nDRY-RUN 共 {len(results)} 条待建渠道（未写入）")
        for r in results:
            print(f"  {r['name']} @ {r['region']} (geo={r['geo']})")
        print("=" * 60)
        return
    success = [r for r in results if r["status"] == "成功"]
    failed = [r for r in results if r["status"] != "成功"]
    print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
    if failed:
        print(f"\n--- 失败 ({len(failed)}) ---")
        for r in failed:
            print(f"  {r['name']} @ {r['region']} (geo={r['geo']})  ({r['status']})")
    print("=" * 60)
