"""Kiro 相关 mode：overage、refresh、export-kiro、import-kiro、kiro 批量"""

from datetime import datetime, timedelta
import asyncio
import json
import logging
import os
import shutil
import sys

from app.core.browser import prewarm_kiro_asset_cache
from app.kiro.api import (
    KIRO_OUTPUT_FILE,
    kiro_ensure_overage,
    kiro_list_first_profile_arn,
    kiro_refresh_access_token,
    kiro_set_overage,
)
from app.kiro.parsing import (
    _load_kiro_records,
    build_kiro_record_from_refresh,
    kiro_records_to_refresh_tokens,
    parse_idc_batch_flags,
    parse_idc_credential_line,
    parse_kiro_input,
    parse_overage_flag,
    parse_refresh_token_input,
    split_kiro_blocks,
)
from app.kiro.register import (
    KIRO_APIKEY_OUTPUT_FILE,
    InsecureBrowserBlocked,
    _prepare_isolated_kiro_home,
    register_kiro,
    register_kiro_apikey,
)

logger = logging.getLogger(__name__)


def _apply_backend_flag(extra: list) -> None:
    """从命令行 `--backend/-b/--browser <值>` 覆盖 KIRO_BROWSER_BACKEND（写进环境变量，
    kiro_browser_backend() 会优先读它）。例：`./run.sh kiro-apikey f.txt --backend safari`。
    合法值：camoufox / cloak / chrome / webkit / safari / botbrowser（大小写不敏感）。"""
    for flag in ("--backend", "--browser", "-b"):
        if flag in extra:
            i = extra.index(flag)
            if i + 1 < len(extra):
                val = extra[i + 1].strip()
                os.environ["KIRO_BROWSER_BACKEND"] = val
                logger.info(f"命令行覆盖浏览器后端：KIRO_BROWSER_BACKEND={val}")
            else:
                print(f"{flag} 需要一个值（camoufox/cloak/chrome/webkit/safari/botbrowser）")
                exit(1)
            return


# overage 模式：切换 Kiro 账号的 overage（超额计费）开关
async def run_overage(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    action = "enable"
    for tok in extra:
        low = tok.lower()
        if low in ("enable", "disable", "on", "off"):
            action = "enable" if low in ("enable", "on") else "disable"
            break
    enabled = (action == "enable")

    # 收集 [{refreshToken, profileArn?}] 任务列表
    # 输入兼容：refresh_tokens.json/kiro.json/单条 refreshToken/每行一个 token 的文本
    tasks: list = []
    if is_file:
        with open(raw_input, "r") as f:
            raw_text = f.read()
        stripped = raw_text.strip()
        parsed = None
        if stripped.startswith(("[", "{")):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                parsed = None
        if isinstance(parsed, dict):
            parsed = parsed.get("accounts") or [parsed]
        if isinstance(parsed, list):
            for item in parsed:
                if not isinstance(item, dict):
                    continue
                tok = item.get("refreshToken") or item.get("refresh_token")
                if not tok:
                    continue
                tasks.append({
                    "refreshToken": tok,
                    "profileArn": item.get("profileArn") or "",
                    "email": item.get("email") or "",
                })
        else:
            for line in raw_text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                tasks.append({"refreshToken": line, "profileArn": "", "email": ""})
    else:
        tasks.append({"refreshToken": raw_input, "profileArn": "", "email": ""})

    if not tasks:
        print("未读取到任何 refreshToken")
        exit(1)

    target_status = "ENABLED" if enabled else "DISABLED"
    logger.info(f"目标: overage = {target_status}，共 {len(tasks)} 个账号")

    ok_count = 0
    fail_count = 0
    for idx, task in enumerate(tasks, 1):
        tag = task["email"] or task["refreshToken"][:24] + "..."
        refreshed = kiro_refresh_access_token(task["refreshToken"])
        access_token = refreshed.get("accessToken") or ""
        profile_arn = task["profileArn"] or refreshed.get("profileArn") or ""
        if not access_token:
            logger.warning(f"[{idx}/{len(tasks)}] {tag} 刷新失败，跳过")
            fail_count += 1
            continue
        if not profile_arn:
            profile_arn = kiro_list_first_profile_arn(access_token)
        if not profile_arn:
            logger.warning(f"[{idx}/{len(tasks)}] {tag} 拿不到 profileArn，跳过")
            fail_count += 1
            continue
        if kiro_set_overage(access_token, profile_arn, enabled):
            ok_count += 1
            logger.info(f"[{idx}/{len(tasks)}] {tag} → {target_status} ✓")
        else:
            fail_count += 1
            logger.warning(f"[{idx}/{len(tasks)}] {tag} 切换失败")

    print(f"完成: 成功 {ok_count} / 失败 {fail_count} / 总计 {len(tasks)}")
    exit(0 if fail_count == 0 else 1)


# refresh 模式：把 refreshToken 字符串转换为 [{refreshToken, provider}] JSON 数组
async def run_refresh(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    provider = "Google"
    if "--provider" in extra:
        i = extra.index("--provider")
        if i + 1 >= len(extra):
            print("--provider 需要一个值")
            exit(1)
        provider = extra[i + 1]
    out_path = "refresh_tokens.json"
    if "--out" in extra:
        i = extra.index("--out")
        if i + 1 >= len(extra):
            print("--out 需要一个文件路径参数")
            exit(1)
        out_path = extra[i + 1]
    append_mode = "--append" in extra

    if is_file:
        with open(raw_input, "r") as f:
            raw_lines = f.readlines()
    else:
        raw_lines = [raw_input]

    tokens = []
    seen = set()
    for line in raw_lines:
        tok = line.strip()
        if not tok or tok.startswith("#"):
            continue
        if tok in seen:
            continue
        seen.add(tok)
        tokens.append(tok)

    if not tokens:
        print("未读取到任何 token")
        exit(1)

    records = [{"refreshToken": t, "provider": provider} for t in tokens]

    if append_mode and os.path.isfile(out_path):
        try:
            with open(out_path, "r") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                raise ValueError("已存在的输出文件不是 JSON 数组，无法追加")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"读取已有输出文件失败：{e}")
            exit(1)
        existing_tokens = {
            item.get("refreshToken")
            for item in existing
            if isinstance(item, dict)
        }
        added = 0
        for rec in records:
            if rec["refreshToken"] not in existing_tokens:
                existing.append(rec)
                existing_tokens.add(rec["refreshToken"])
                added += 1
        records = existing
        logger.info(f"追加 {added} 条新记录（去重后总计 {len(records)}）到 {out_path}")
    else:
        logger.info(f"写入 {len(records)} 条记录到 {out_path}")

    with open(out_path, "w") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(json.dumps(records, ensure_ascii=False, indent=2))
    return


# export-kiro 模式：把 kiro 账号记录(JSON) 转成 [{refreshToken, provider}] 数组
async def run_export_kiro(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    provider_override = ""
    out_path = "refresh_tokens.json"
    append_mode = "--append" in extra
    if "--provider" in extra:
        i = extra.index("--provider")
        if i + 1 >= len(extra):
            print("--provider 需要一个值")
            exit(1)
        provider_override = extra[i + 1]
    if "--out" in extra:
        i = extra.index("--out")
        if i + 1 >= len(extra):
            print("--out 需要一个文件路径参数")
            exit(1)
        out_path = extra[i + 1]

    try:
        kiro_records = _load_kiro_records(raw_input, is_file)
    except (json.JSONDecodeError, ValueError, OSError) as e:
        print(f"读取 kiro 输入失败: {e}")
        exit(1)

    records = kiro_records_to_refresh_tokens(kiro_records, provider_override)
    if not records:
        print("未从输入中提取到任何 refreshToken")
        exit(1)

    if append_mode and os.path.isfile(out_path):
        try:
            with open(out_path, "r") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                raise ValueError("已存在的输出文件不是 JSON 数组，无法追加")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"读取已有输出文件失败：{e}")
            exit(1)
        existing_tokens = {
            item.get("refreshToken")
            for item in existing
            if isinstance(item, dict)
        }
        added = 0
        for rec in records:
            if rec["refreshToken"] not in existing_tokens:
                existing.append(rec)
                existing_tokens.add(rec["refreshToken"])
                added += 1
        records = existing
        logger.info(f"追加 {added} 条新记录（去重后总计 {len(records)}）到 {out_path}")
    else:
        logger.info(f"写入 {len(records)} 条记录到 {out_path}")

    with open(out_path, "w") as f:
        json.dump(records, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(json.dumps(records, ensure_ascii=False, indent=2))
    return


# import-kiro 模式：把 [{refreshToken, provider}] 反向生成完整 kiro.json 条目
async def run_import_kiro(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    provider_override = ""
    out_path = KIRO_OUTPUT_FILE
    label_override = ""
    # overage 配置：None=不处理，True=enable，False=disable
    overage_action: bool | None = None
    if "--provider" in extra:
        i = extra.index("--provider")
        if i + 1 >= len(extra):
            print("--provider 需要一个值")
            exit(1)
        provider_override = extra[i + 1]
    if "--out" in extra:
        i = extra.index("--out")
        if i + 1 >= len(extra):
            print("--out 需要一个文件路径参数")
            exit(1)
        out_path = extra[i + 1]
    if "--label" in extra:
        i = extra.index("--label")
        if i + 1 >= len(extra):
            print("--label 需要一个值")
            exit(1)
        label_override = extra[i + 1]
    try:
        overage_action = parse_overage_flag(extra)
    except ValueError as e:
        print(e)
        exit(1)

    if not is_file:
        stripped = raw_input.strip()
        if not (stripped.startswith("{") or stripped.startswith("[")
                or "----" in stripped or "📦" in stripped):
            print(f"输入既不是已存在的文件，也不是 JSON/卡密/📦 块: {raw_input!r}")
            print("用法: python main.py import-kiro <file>")
            print("  JSON: '{\"refreshToken\":\"aor...\",\"clientId\":\"...\",\"clientSecret\":\"eyJ...\",\"provider\":\"BuilderId\"}'")
            print("  卡密: 'email----password----refreshToken----clientId----clientSecret'")
            print("  📦 块: '📦 Account #1\\n🔸 mail: RefreshToken\\n🔸 pass: <refreshToken>\\n🔸 2fa: <email>'")
            exit(1)
    try:
        items = parse_refresh_token_input(raw_input, is_file)
    except (json.JSONDecodeError, ValueError, OSError) as e:
        print(f"读取输入失败: {e}")
        exit(1)
    if not items:
        print("未提取到任何 refreshToken")
        exit(1)

    existing = []
    if os.path.isfile(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
        except Exception as e:
            logger.warning(f"读取已有 {out_path} 失败，将作为新文件创建: {e}")
            existing = []
    existing_tokens = {
        r.get("refreshToken") for r in existing
        if isinstance(r, dict) and r.get("refreshToken")
    }

    added = 0
    skipped = 0
    overage_ok = 0
    overage_fail = 0
    for item in items:
        tok = item["refreshToken"]

        # 如果开了 overage：用 refreshToken 换 accessToken+profileArn，顺便回填到新记录
        access_token = ""
        profile_arn = ""
        expires_at = None
        if overage_action is not None:
            refreshed = kiro_refresh_access_token(tok)
            access_token = refreshed.get("accessToken") or ""
            profile_arn = refreshed.get("profileArn") or ""
            expires_in = refreshed.get("expiresIn")
            if access_token and isinstance(expires_in, (int, float)):
                expires_at = (datetime.utcnow() + timedelta(seconds=int(expires_in))).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            if access_token and not profile_arn:
                profile_arn = kiro_list_first_profile_arn(access_token)

            tag = item.get("email") or tok[:24] + "..."
            if access_token and profile_arn:
                if kiro_set_overage(access_token, profile_arn, overage_action):
                    overage_ok += 1
                    logger.info(f"{tag} overage → {'ENABLED' if overage_action else 'DISABLED'} ✓")
                else:
                    overage_fail += 1
            else:
                overage_fail += 1
                logger.warning(f"{tag} overage 跳过：accessToken 或 profileArn 缺失")

        if tok in existing_tokens:
            skipped += 1
            continue
        record = build_kiro_record_from_refresh(
            refresh_token=tok,
            provider=provider_override or item.get("provider") or "Google",
            label=label_override,
            email=item.get("email", ""),
            password=item.get("password"),
            client_id=item.get("clientId"),
            client_secret=item.get("clientSecret"),
            region=item.get("region"),
        )
        # 顺手把 refresh 拿到的字段补进去，省得 kiro.json 里全是空字段
        if access_token:
            record["accessToken"] = access_token
        if profile_arn:
            record["profileArn"] = profile_arn
        if expires_at:
            record["expiresAt"] = expires_at
        existing.append(record)
        existing_tokens.add(tok)
        added += 1

    if added > 0:
        tmp_path = f"{out_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, out_path)

    summary = f"\n完成: 新增 {added} 条，跳过重复 {skipped} 条，输出文件 {out_path}（现共 {len(existing)} 条）"
    if overage_action is not None:
        summary += f"；overage {'ENABLED' if overage_action else 'DISABLED'} 成功 {overage_ok} / 失败 {overage_fail}"
    print(summary)
    return


# kiro 模式：批量登录 kiro-cli，记录追加到 kiro.json
# 注意：kiro 流程现在由 register_kiro 内部管 Chrome 生命周期
# （抓 URL 之后再启 Playwright Chrome，避免 AppleScript 被劫持）
async def run_kiro_batch(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    _apply_backend_flag(extra)
    out_path = KIRO_OUTPUT_FILE
    if "--out" in extra:
        i = extra.index("--out")
        if i + 1 >= len(extra):
            print("--out 需要一个文件路径参数")
            exit(1)
        out_path = extra[i + 1]
    try:
        overage_action = parse_overage_flag(extra)
        idc_ctx = parse_idc_batch_flags(extra)
    except ValueError as e:
        print(e)
        exit(1)

    with open(raw_input, "r") as f:
        content = f.read()
    if idc_ctx is not None:
        # 共享 IDC 上下文：整文件按 `username | password` 逐行处理
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        logger.info(
            f"读取到 {len(lines)} 个 IDC 账号，start_url={idc_ctx[0]} region={idc_ctx[1]}，开始批量登录 Kiro..."
        )
    else:
        lines = split_kiro_blocks(content)
        logger.info(f"读取到 {len(lines)} 个账号块，开始批量登录 Kiro...")
    if overage_action is not None:
        logger.info(f"将在登录成功后切换 overage = {'ENABLED' if overage_action else 'DISABLED'}")
    logger.info(f"登录成功记录将写入 {out_path}")

    # 提前解析每行 → parsed_list[i] 为 (parsed_tuple, None) 或 (None, err_msg)。
    # 既用于判定能否并发（是否含 builderid/github 这类 Terminal 路径的行），
    # 也直接复用给登录，避免重复解析。
    parsed_list = []
    for line in lines:
        try:
            if idc_ctx is not None:
                parsed_list.append((parse_idc_credential_line(line, idc_ctx[0], idc_ctx[1]), None))
            else:
                parsed_list.append((parse_kiro_input(line), None))
        except ValueError as e:
            parsed_list.append((None, str(e)))

    # 并发度：IDC 行（pexpect + 每账号独立 $HOME 可隔离 kiro-cli token 库）可并发；
    # builderid/github 走 Terminal.app + `pkill -f` 共享路径，并发会互相误杀，只要
    # 含一行这种就整批强制串行。解析失败行不 spawn 任何东西，不影响并发安全性。
    # 默认：可并发批量 3，否则 1（串行）。用 `-c/--conc/--concurrency N` 覆盖。
    has_social = any(p and p[0] in ("builderid", "github") for p, _ in parsed_list)
    concurrency = None
    conc_flag = next((f for f in ("--concurrency", "--conc", "-c") if f in extra), None)
    if conc_flag is not None:
        i = extra.index(conc_flag)
        if i + 1 >= len(extra):
            print(f"{conc_flag} 需要一个数字参数")
            exit(1)
        try:
            concurrency = max(1, int(extra[i + 1]))
        except ValueError:
            print(f"{conc_flag} 参数必须是整数")
            exit(1)
    if concurrency is None:
        concurrency = 1 if has_social else 3
    if concurrency > 1 and has_social:
        logger.warning("批量含 builderid/github（Terminal.app 共享路径），无法安全并发，强制串行")
        concurrency = 1
    if concurrency > 1:
        from app.core.browser import kiro_browser_backend
        if kiro_browser_backend() == "safari":
            logger.warning("safari 后端（safaridriver 单会话）无法并发，强制串行")
            concurrency = 1
    use_iso = concurrency > 1
    if concurrency > 1:
        logger.info(
            f"并发登录：最多同时 {concurrency} 个账号"
            f"（kiro-cli 数据目录按账号隔离 $HOME，token 不串号）"
        )

    total = len(lines)
    results = [None] * total  # 按输入顺序回填，汇总保持原序
    overage_ok = 0
    overage_fail = 0
    sem = asyncio.Semaphore(concurrency)

    async def _login_one(idx: int, line: str) -> dict:
        parsed, err = parsed_list[idx - 1]
        if err is not None:
            logger.warning(f"[{idx}/{total}] 解析失败: {err}")
            return {"email": line[:30], "status": "解析失败"}

        # 准备 base_record：IDC mode 额外塞 username/start_url 两列，
        # 失败汇总分列打印方便复制（单独 copy username 或 URL 不再被 @ 黏在一起）
        base_record = {}
        if parsed[0] in ("builderid", "github"):
            label = parsed[1]
        elif parsed[0] == "idc":
            label = f"{parsed[2]}@{parsed[1]}"
            base_record["idc_user"] = parsed[2]
            base_record["idc_url"] = parsed[1]
        else:
            label = str(parsed)[:40]
        logger.info(f"[{idx}/{total}] 登录 Kiro ({parsed[0]}): {label}")

        iso_home = ""
        try:
            if use_iso:
                iso_home, _ = _prepare_isolated_kiro_home()
            record = await register_kiro(parsed, output_file=out_path, iso_home=iso_home)
            res = {**base_record,
                   "email": record.get("email") or label, "status": "成功",
                   "userId": record.get("userId")}
            if overage_action is not None:
                tag = record.get("email") or label
                if kiro_ensure_overage(record, overage_action):
                    res["_overage"] = True
                    logger.info(f"[{idx}/{total}] {tag} overage → {'ENABLED' if overage_action else 'DISABLED'} ✓")
                else:
                    res["_overage"] = False
                    logger.warning(f"[{idx}/{total}] {tag} overage 切换失败")
            return res
        except InsecureBrowserBlocked as e:
            logger.warning(f"[{idx}/{total}] {label}: 跳过 - {e}")
            return {**base_record, "email": label, "status": f"跳过: {e}"}
        except Exception as e:
            logger.warning(f"[{idx}/{total}] {label}: 失败 - {e}")
            return {**base_record, "email": label, "status": f"失败: {e}"}
        finally:
            if iso_home:
                shutil.rmtree(iso_home, ignore_errors=True)

    async def _guarded(idx: int, line: str) -> None:
        async with sem:  # 限流：最多 concurrency 个账号同时在跑
            results[idx - 1] = await _login_one(idx, line)

    # 批量开跑前先预热一次静态资源基准缓存：打开 signin 拉 assets.app.kiro.dev 的
    # chunk（不登录），后续每个账号 profile 直接播种，免得各自冷加载再撞代理拦截。
    # 预热失败只降级为冷加载，不阻断批量。
    await prewarm_kiro_asset_cache()

    try:
        await asyncio.gather(*(_guarded(idx, line)
                               for idx, line in enumerate(lines, 1)))
        # overage 统计延后到全部完成再数（并发下计数器无法安全累加），顺带去掉内部标记
        for r in results:
            if r is None:
                continue
            ov = r.pop("_overage", None)
            if ov is True:
                overage_ok += 1
            elif ov is False:
                overage_fail += 1
    finally:
        print("\n" + "=" * 60)
        print("批量登录 Kiro 结果汇总")
        print("=" * 60)
        success = [r for r in results if r and r["status"] == "成功"]
        failed = [r for r in results if r and r["status"] != "成功"]
        print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
        if overage_action is not None:
            print(f"overage {'ENABLED' if overage_action else 'DISABLED'}: 成功 {overage_ok}  失败 {overage_fail}")
        if success:
            print(f"\n--- 成功账号 ({len(success)}) ---")
            for r in success:
                print(f"  {r['email']}  (userId={r.get('userId')})")
        if failed:
            print(f"\n--- 失败账号 ({len(failed)}) ---")
            # IDC 失败行分两列：username 和 start_url 各自一列方便复制
            idc_failed = [r for r in failed if r.get("idc_user")]
            other_failed = [r for r in failed if not r.get("idc_user")]
            if idc_failed:
                user_w = max(len(r["idc_user"]) for r in idc_failed)
                url_w = max(len(r["idc_url"]) for r in idc_failed)
                # 表头 + 用 ` | ` 分隔的对齐表
                print(f"  {'username'.ljust(user_w)} | {'start_url'.ljust(url_w)} | status")
                print(f"  {'-' * user_w}-+-{'-' * url_w}-+-{'-' * 30}")
                for r in idc_failed:
                    print(f"  {r['idc_user'].ljust(user_w)} | {r['idc_url'].ljust(url_w)} | {r['status']}")
            if other_failed:
                if idc_failed:
                    print()  # 跟 IDC 表分隔
                for r in other_failed:
                    print(f"  {r['email']}  ({r['status']})")
        print("=" * 60)
    return


def _append_apikey_records(records: list, out_path: str) -> tuple:
    """只导出 apiKey：把新抓到的 ksk_ key 逐行去重追加进 out_path（纯文本，每行一个）。
    返回 (新增数, 总数)。原子写（.tmp + os.replace）。"""
    existing = []
    if os.path.isfile(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                existing = [l.strip() for l in f if l.strip()]
        except Exception as e:
            logger.warning(f"读取已有 {out_path} 失败，将作为新文件创建: {e}")
            existing = []
    seen = set(existing)
    added = 0
    for r in records:
        key = r.get("apiKey")
        if key and key not in seen:
            existing.append(key)
            seen.add(key)
            added += 1
    tmp = f"{out_path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(existing))
        if existing:
            f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, out_path)
    return added, len(existing)


# kiro-apikey 模式：企业号(IDC)网页登录 app.kiro.dev → /settings/api-keys 建 API Key（ksk_）
# 单条记录或文件批量。仅支持 IDC（Your organization）账号。
async def run_kiro_apikey(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]
    _apply_backend_flag(extra)
    out_path = KIRO_APIKEY_OUTPUT_FILE
    if "--out" in extra:
        i = extra.index("--out")
        if i + 1 >= len(extra):
            print("--out 需要一个文件路径参数")
            exit(1)
        out_path = extra[i + 1]
    key_name = ""
    if "--key-name" in extra:
        i = extra.index("--key-name")
        if i + 1 >= len(extra):
            print("--key-name 需要一个值")
            exit(1)
        key_name = extra[i + 1]
    try:
        idc_ctx = parse_idc_batch_flags(extra)
    except ValueError as e:
        print(e)
        exit(1)

    # 收集输入行：文件批量 or 单条
    if is_file:
        with open(raw_input, "r") as f:
            content = f.read()
        if idc_ctx is not None:
            # 共享 IDC 上下文：整文件按 `username | password` 逐行
            lines = [l.strip() for l in content.splitlines()
                     if l.strip() and not l.strip().startswith("#")]
            logger.info(
                f"读取到 {len(lines)} 个 IDC 账号，start_url={idc_ctx[0]} "
                f"region={idc_ctx[1]}，开始批量生成 API Key..."
            )
        else:
            lines = split_kiro_blocks(content)
            logger.info(f"读取到 {len(lines)} 个账号块，开始批量生成 API Key...")
    else:
        lines = [raw_input]

    # 预解析：apikey 只支持 IDC，其它 provider 直接标失败
    parsed_list = []
    for line in lines:
        try:
            if idc_ctx is not None:
                parsed = parse_idc_credential_line(line, idc_ctx[0], idc_ctx[1])
            else:
                parsed = parse_kiro_input(line)
            if parsed[0] != "idc":
                parsed_list.append((None, f"非 IDC 账号（{parsed[0]}），apikey 模式仅支持企业号"))
            else:
                parsed_list.append((parsed, None))
        except ValueError as e:
            parsed_list.append((None, str(e)))

    # 并发度：每账号独立 Camoufox Firefox + 独立 profile，可并发；默认串行 1，`-c N` 覆盖
    concurrency = 1
    conc_flag = next((f for f in ("--concurrency", "--conc", "-c") if f in extra), None)
    if conc_flag is not None:
        i = extra.index(conc_flag)
        if i + 1 >= len(extra):
            print(f"{conc_flag} 需要一个数字参数")
            exit(1)
        try:
            concurrency = max(1, int(extra[i + 1]))
        except ValueError:
            print(f"{conc_flag} 参数必须是整数")
            exit(1)
    if concurrency > 1:
        from app.core.browser import kiro_browser_backend
        if kiro_browser_backend() == "safari":
            logger.warning("safari 后端（safaridriver 单会话）无法并发，强制串行")
            concurrency = 1
    logger.info(f"API Key 结果将写入 {out_path}（并发 {concurrency}）")

    total = len(lines)
    results = [None] * total
    sem = asyncio.Semaphore(concurrency)
    # 每抓到一个 key 就立即去重追加落盘（而不是全跑完再一次性写整个文件）：
    # Kiro API Key 只在弹窗显示一次、无法二次获取，进程中途中断/崩溃也不能丢已建的 key。
    # 并发下多任务同写一个文件，用锁串行化 read-modify-write，避免相互覆盖。
    write_lock = asyncio.Lock()
    added_total = 0
    grand_total = 0

    async def _one(idx: int, line: str) -> dict:
        nonlocal added_total, grand_total
        parsed, err = parsed_list[idx - 1]
        if err is not None:
            logger.warning(f"[{idx}/{total}] 解析失败/跳过: {err}")
            return {"email": line[:40], "status": f"跳过: {err}"}
        label = f"{parsed[2]}@{parsed[1]}"
        logger.info(f"[{idx}/{total}] 生成 API Key: {label}")
        try:
            record = await register_kiro_apikey(parsed, output_file=out_path, key_name=key_name)
            async with write_lock:
                a, grand_total = _append_apikey_records([record], out_path)
                added_total += a
            return {**record, "status": "成功"}
        except Exception as e:
            logger.warning(f"[{idx}/{total}] {label}: 失败 - {e}")
            return {"email": label, "username": parsed[2], "startUrl": parsed[1],
                    "status": f"失败: {e}"}

    async def _guarded(idx: int, line: str) -> None:
        async with sem:
            results[idx - 1] = await _one(idx, line)

    # 批量开跑前先预热一次静态资源基准缓存：打开 signin 拉 assets.app.kiro.dev 的
    # chunk（不登录），后续每个账号 profile 直接播种，免各自冷加载再撞代理限流。
    # 预热失败只降级为冷加载，不阻断批量。
    await prewarm_kiro_asset_cache()

    try:
        await asyncio.gather(*(_guarded(idx, line)
                               for idx, line in enumerate(lines, 1)))
    finally:
        success = [r for r in results if r and r.get("status") == "成功"]
        failed = [r for r in results if r and r.get("status") != "成功"]
        # key 已在 _one 里逐个去重追加落盘，这里只汇总数字
        added = added_total
        print("\n" + "=" * 60)
        print("批量生成 Kiro API Key 结果汇总")
        print("=" * 60)
        print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
        if success:
            print(f"新增写入 {out_path}: {added} 条（现共 {grand_total} 条）")
            print(f"\n--- 成功账号 ({len(success)}) ---")
            for r in success:
                key = r.get("apiKey") or ""
                print(f"  {r.get('email')}  keyName={r.get('keyName')}  {key}")
        if failed:
            print(f"\n--- 失败账号 ({len(failed)}) ---")
            for r in failed:
                print(f"  {r.get('email')}  ({r.get('status')})")
        print("=" * 60)
    return
