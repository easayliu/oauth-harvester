"""subus / bedrock 推送相关 mode：oauth、subus、bedrock"""

import logging
import os
import sys
import time

from app.accounts.subus import (
    aws_region_to_geo,
    register_bedrock_account,
    register_subus_account,
    register_subus_oauth_account,
    subus_exchange_code,
    subus_generate_auth_url,
)
from app.core.parsing import (
    collect_cookie_jars,
    extract_sessionkeys_from_text,
    parse_session_input,
    parse_subus_input,
)
from app.settings import (
    BEDROCK_API_GLOBAL_SOURCE_REGION,
    BEDROCK_API_NAME_PREFIX,
    BEDROCK_API_REGIONS,
    SUBUS_API_ADMIN_TOKEN,
)
from app.ssh.remote import SessionLoginError, open_auth_url_and_get_code

logger = logging.getLogger(__name__)


# oauth 模式：用 sessionKey 登录 claude.ai，走 subus generate-auth-url → 授权拿 code →
#            exchange-code 拿 OAuth token → 注册为 type=oauth 的 subus 账号
async def run_oauth(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]

    # --name <name> 覆盖账号名（默认用 exchange-code 返回的 email_address）
    name_override = ""
    if "--name" in extra:
        i = extra.index("--name")
        if i + 1 < len(extra):
            name_override = extra[i + 1]

    # --group-ids 20,21 覆盖默认分组
    group_ids = None
    if "--group-ids" in extra:
        i = extra.index("--group-ids")
        if i + 1 < len(extra):
            group_ids = [int(x) for x in extra[i + 1].split(",") if x.strip()]

    if not SUBUS_API_ADMIN_TOKEN:
        print("SUBUS_API_ADMIN_TOKEN 未配置，无法推送")
        exit(1)

    # 收集待处理的 (label, session_key)：
    #   目录 → 扫描其中所有 .crash/.json，每个 cookie 文件一条（批量）
    #   cookie JSON（文件或直接粘贴）→ 支持单个 jar / 多个 jar（数组的数组 / JSONL），每个 jar 一条
    #   普通文本文件 → 每行一条 session；否则按单条 session 输入解析
    targets = []
    if os.path.isdir(raw_input):
        for label, sk, _ in collect_cookie_jars(raw_input):
            targets.append((label, sk))
    else:
        content = ""
        if is_file:
            with open(raw_input, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            content = raw_input
        cstrip = content.strip()

        if cstrip[:1] in ("[", "{"):
            # cookie JSON：单个或多个 jar，只取每个 jar 里 name==sessionKey 的 value
            # （不能用 parse_session_input，否则正则会先匹配到 routingHint 的 sk-ant-rh-...）
            sks = extract_sessionkeys_from_text(content)
            if not sks:
                print("未能从 cookie JSON 中提取到任何 sessionKey")
                exit(1)
            base = os.path.basename(raw_input) if is_file else "cookie-json"
            for i, sk in enumerate(sks, 1):
                label = f"{base}#{i}" if len(sks) > 1 else base
                targets.append((label, sk))
        elif is_file:
            # 普通文本文件：每行一条 session（同 session 模式格式）
            for line in cstrip.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    email, _, sk = parse_session_input(line)
                    targets.append((email or sk[:16], sk))
                except ValueError as e:
                    logger.warning(f"解析失败，跳过: {line[:40]} ({e})")
        else:
            email, _, sk = parse_session_input(raw_input)
            targets.append((email or sk[:16], sk))

    if not targets:
        print("无可处理的 sessionKey")
        exit(0)

    logger.info(f"oauth 模式：准备处理 {len(targets)} 个 sessionKey...")
    results = []
    for idx, (label, sk) in enumerate(targets, 1):
        logger.info(f"[{idx}/{len(targets)}] {label} 开始 OAuth 授权流程...")
        try:
            auth_url, session_id = subus_generate_auth_url()
            if not auth_url:
                results.append({"label": label, "status": "generate-auth-url 失败"})
                continue

            # 登录失败（sessionKey 失效）→ 抛 SessionLoginError，跳过后续 exchange/register
            try:
                code = await open_auth_url_and_get_code(
                    auth_url, sk, tag=f"oauth_{idx}", raise_on_login_fail=True
                )
            except SessionLoginError:
                logger.warning(f"[{idx}/{len(targets)}] {label} sessionKey 登录失败，跳过后续流程")
                results.append({"label": label, "status": "登录失败（sessionKey 失效），已跳过"})
                continue
            if not code:
                results.append({"label": label, "status": "登录成功但未取到 code（授权页异常）"})
                continue
            logger.info(f"[{idx}/{len(targets)}] 获取到 code ({len(code)} 字符)")

            token_data = subus_exchange_code(session_id, code)
            if not token_data:
                results.append({"label": label, "status": "exchange-code 失败"})
                continue

            # 批量时每条用各自的 email；单条且传了 --name 时用 --name
            this_name = name_override if (name_override and len(targets) == 1) else ""
            ok = register_subus_oauth_account(token_data, name=this_name, group_ids=group_ids)
            acct = token_data.get("email_address", label)
            results.append({"label": acct, "status": "成功" if ok else "注册失败"})
        except Exception as e:
            logger.error(f"[{idx}/{len(targets)}] {label} 出错: {e}")
            results.append({"label": label, "status": f"异常: {e}"})

    print("\n" + "=" * 60)
    print("subus oauth 推送结果汇总")
    print("=" * 60)
    success = [r for r in results if r["status"] == "成功"]
    failed = [r for r in results if r["status"] != "成功"]
    print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
    if failed:
        print(f"\n--- 失败 ({len(failed)}) ---")
        for r in failed:
            print(f"  {r['label']}  ({r['status']})")
    print("=" * 60)
    return


# subus 模式：把 (email, api_key, workspace_id) 推送到 subus admin /api/v1/admin/accounts
async def run_subus(mode: str, raw_input: str, is_file: bool):
    if is_file:
        with open(raw_input, "r") as f:
            lines = [l.strip() for l in f.readlines() if l.strip() and not l.strip().startswith("#")]
    else:
        lines = [raw_input.strip()]

    if not lines:
        print("无可推送的行")
        exit(0)

    logger.info(f"准备推送 {len(lines)} 条到 subus admin API...")
    results = []
    for idx, line in enumerate(lines, 1):
        try:
            email, api_key, workspace_id = parse_subus_input(line)
        except ValueError as e:
            logger.warning(f"[{idx}/{len(lines)}] 解析失败: {e}")
            results.append({"label": line[:40], "status": f"解析失败: {e}"})
            continue
        if not api_key or not workspace_id:
            logger.warning(f"[{idx}/{len(lines)}] {email}: api_key 或 workspace_id 为空，跳过")
            results.append({"label": email, "status": "字段为空"})
            continue
        ok = register_subus_account(email, api_key, workspace_id)
        results.append({"label": email, "status": "成功" if ok else "失败"})

    print("\n" + "=" * 60)
    print("subus 推送结果汇总")
    print("=" * 60)
    success = [r for r in results if r["status"] == "成功"]
    failed = [r for r in results if r["status"] != "成功"]
    print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
    if failed:
        print(f"\n--- 失败 ({len(failed)}) ---")
        for r in failed:
            print(f"  {r['label']}  ({r['status']})")
    print("=" * 60)
    return


# bedrock 模式：把 Bedrock API Key 按区域逐个推送到 gptus admin /api/v1/admin/accounts
# 命名: aws-{geo}-{ts} 或 aws-{geo}-{seq}-{ts}（同 geo 多条时加 seq），ts 为批次时间戳
async def run_bedrock(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]

    # --regions us-west-2,us-east-1  覆盖默认区域
    regions = list(BEDROCK_API_REGIONS)
    if "--regions" in extra:
        i = extra.index("--regions")
        if i + 1 >= len(extra):
            print("--regions 需要一个逗号分隔的区域列表")
            exit(1)
        regions = [r.strip() for r in extra[i + 1].split(",") if r.strip()]

    if is_file:
        with open(raw_input, "r") as f:
            api_keys = [l.strip() for l in f.readlines() if l.strip() and not l.strip().startswith("#")]
    else:
        api_keys = [raw_input.strip()]

    if not api_keys:
        print("无可推送的 api_key")
        exit(0)
    if not regions:
        print("无可用区域")
        exit(1)

    # --no-global  跳过末尾追加的强制 global 条目（默认追加）
    skip_global = "--no-global" in extra
    # --global-region <region>  覆盖强制 global 条目的 source region
    global_region = BEDROCK_API_GLOBAL_SOURCE_REGION
    if "--global-region" in extra:
        i = extra.index("--global-region")
        if i + 1 >= len(extra):
            print("--global-region 需要一个 region 字符串")
            exit(1)
        global_region = extra[i + 1].strip()

    # 批次时间戳（所有 api_key × region 共享一个，便于一眼分辨一批）
    batch_ts = time.strftime("%Y%m%d%H%M%S")

    # 先统计每个 geo 在整批里出现几次，决定是否要加 seq 后缀
    geo_total = {}
    for _ in api_keys:
        for region in regions:
            g = aws_region_to_geo(region)
            geo_total[g] = geo_total.get(g, 0) + 1
        if not skip_global:
            geo_total["global"] = geo_total.get("global", 0) + 1

    def _make_name(geo: str, seq_counter: dict) -> str:
        seq_counter[geo] = seq_counter.get(geo, 0) + 1
        if geo_total.get(geo, 0) <= 1:
            return f"{BEDROCK_API_NAME_PREFIX}-{geo}-{batch_ts}"
        return f"{BEDROCK_API_NAME_PREFIX}-{geo}-{seq_counter[geo]}-{batch_ts}"

    per_key = len(regions) + (0 if skip_global else 1)
    total = len(api_keys) * per_key
    logger.info(f"准备推送 {len(api_keys)} 个 api_key × {per_key} 条 "
                f"({len(regions)} 区域{'' if skip_global else f' + 1 global@{global_region}'}) "
                f"= {total} 条到 gptus admin API (批次 ts={batch_ts})")

    results = []
    geo_seq = {}
    idx = 0
    for k_idx, api_key in enumerate(api_keys, 1):
        for region in regions:
            idx += 1
            geo = aws_region_to_geo(region)
            name = _make_name(geo, geo_seq)
            logger.info(f"[{idx}/{total}] {name}  region={region}  geo={geo}  key={api_key[:12]}...")
            ok = register_bedrock_account(api_key, region, name)
            results.append({"name": name, "region": region, "geo": geo,
                            "status": "成功" if ok else "失败", "global": False})
        if not skip_global:
            idx += 1
            name = _make_name("global", geo_seq)
            logger.info(f"[{idx}/{total}] {name}  region={global_region} [force global]  key={api_key[:12]}...")
            ok = register_bedrock_account(api_key, global_region, name, force_global=True)
            results.append({"name": name, "region": global_region, "geo": "global",
                            "status": "成功" if ok else "失败", "global": True})

    print("\n" + "=" * 60)
    print(f"gptus (bedrock) 推送结果汇总  批次 ts={batch_ts}")
    print("=" * 60)
    success = [r for r in results if r["status"] == "成功"]
    failed = [r for r in results if r["status"] != "成功"]
    print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
    if failed:
        print(f"\n--- 失败 ({len(failed)}) ---")
        for r in failed:
            tag = " [global]" if r.get("global") else ""
            print(f"  {r['name']} @ {r['region']}{tag}  ({r['status']})")
    print("=" * 60)
    return
