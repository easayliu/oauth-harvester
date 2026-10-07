"""Claude 相关 mode：batch 批量检测、claude 批量注册"""

import logging
import os

from app.accounts.claude import (
    batch_check_cookie_jars,
    batch_check_sessions,
    claude_login_after_google,
    print_batch_results,
    register_claude,
)
from app.accounts.google_auth import change_password, google_login
from app.core.browser import (
    cloak_browser_session,
    google_session_state_path,
    new_camoufox_context,
    save_google_session,
)
from app.core.parsing import collect_cookie_jars, looks_like_cookie_jar, parse_input
from app.settings import GOOGLE_NEW_PASSWORD

logger = logging.getLogger(__name__)


# batch 模式：读取文件，批量检查 session
async def run_batch(mode: str, raw_input: str, is_file: bool):
    is_dir = os.path.isdir(raw_input)
    if not is_file and not is_dir:
        print(f"文件/目录不存在: {raw_input}")
        exit(1)

    # 目录 或 cookie 导出文件（.crash/.json）→ 走 cookie 检查
    if is_dir or (is_file and looks_like_cookie_jar(raw_input)):
        jars = collect_cookie_jars(raw_input)
        if not jars:
            print("未找到可解析的 cookie 文件（.crash/.json，且含 sessionKey）")
            exit(1)
        logger.info(f"读取到 {len(jars)} 个 cookie 文件，开始批量检查...")
        async with cloak_browser_session() as browser:
            results = await batch_check_cookie_jars(browser, jars)
            print_batch_results(results)
        return

    # 否则按文本行（email----password----sessionKey）
    with open(raw_input, "r") as f:
        lines = [l for l in f.readlines() if l.strip()]
    logger.info(f"读取到 {len(lines)} 个账号，开始批量检查...")

    async with cloak_browser_session() as browser:
        results = await batch_check_sessions(browser, lines)
        print_batch_results(results)
    return


# claude 模式：支持文件批量登录
async def run_claude_batch(mode: str, raw_input: str, is_file: bool):
    with open(raw_input, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    logger.info(f"读取到 {len(lines)} 个账号，开始批量登录 Claude...")

    results = []
    async with cloak_browser_session() as browser:
        try:
            for idx, line in enumerate(lines, 1):
                try:
                    email, password, totp_secret = parse_input(line)
                except ValueError as e:
                    logger.warning(f"[{idx}/{len(lines)}] 解析失败: {e}")
                    results.append({"email": line[:30], "status": "解析失败"})
                    continue

                logger.info(f"[{idx}/{len(lines)}] 登录 Claude: {email}")
                # 复用已保存的 Google 登录态（跨次跑逐渐让 Google 信任本设备，
                # 同一浏览器新开 tab 打开 gmail 不再被要求重新登录）
                context = await new_camoufox_context(
                    browser, storage_state=google_session_state_path(email)
                )
                try:
                    session_key = await register_claude(context, email, password, totp_secret)
                    # 无论是否拿到 sessionKey，登录动作已在此 context 建立 Google 会话，落盘复用
                    await save_google_session(context, email)
                    if session_key:
                        logger.info(f"[{idx}/{len(lines)}] {email}: 登录成功")
                        results.append({"email": email, "password": password, "session_key": session_key, "status": "成功"})
                        # 追加到 session.txt
                        with open("session.txt", "a") as f:
                            f.write(f"{email}----{password}----{session_key}\n")
                    else:
                        logger.warning(f"[{idx}/{len(lines)}] {email}: 未获取到 sessionKey")
                        results.append({"email": email, "status": "未获取到sessionKey"})
                except Exception as e:
                    logger.warning(f"[{idx}/{len(lines)}] {email}: 失败 - {e}")
                    results.append({"email": email, "status": f"失败: {e}"})
                finally:
                    await context.close()
        finally:
            # 打印汇总
            print("\n" + "=" * 60)
            print("批量登录 Claude 结果汇总")
            print("=" * 60)
            success = [r for r in results if r["status"] == "成功"]
            failed = [r for r in results if r["status"] != "成功"]
            print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
            if success:
                print(f"\n--- 成功账号 ({len(success)}) ---")
                for r in success:
                    print(f"  {r['email']}")
            if failed:
                print(f"\n--- 失败账号 ({len(failed)}) ---")
                for r in failed:
                    print(f"  {r['email']}  ({r['status']})")
            print("=" * 60)
    return


# password-claude 模式：先登录 Google 并改密，再接着登录 Claude（同一会话，不重复登 Google）
async def run_password_claude_batch(mode: str, raw_input: str, is_file: bool):
    with open(raw_input, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    logger.info(f"读取到 {len(lines)} 个账号，开始批量『改密 + 登录 Claude』...")

    results = []
    async with cloak_browser_session() as browser:
        try:
            for idx, line in enumerate(lines, 1):
                try:
                    email, password, totp_secret = parse_input(line)
                except ValueError as e:
                    logger.warning(f"[{idx}/{len(lines)}] 解析失败: {e}")
                    results.append({"email": line[:30], "status": "解析失败"})
                    continue

                logger.info(f"[{idx}/{len(lines)}] 改密 + 登录 Claude: {email}")
                context = await new_camoufox_context(
                    browser, storage_state=google_session_state_path(email)
                )
                try:
                    # 步骤1: 登录 Google（只登一次；已有会话则自动跳过登录）
                    page = await google_login(context, email, password, totp_secret)

                    # 步骤2: 改密（已是新密码则跳过）；后续统一用有效密码
                    if password == GOOGLE_NEW_PASSWORD:
                        logger.info(f"[{idx}/{len(lines)}] {email}: 密码已是最新，跳过改密")
                        pwd_status = "已是最新"
                    else:
                        await change_password(context, page, password, GOOGLE_NEW_PASSWORD, totp_secret)
                        logger.info(f"[{idx}/{len(lines)}] {email}: 密码修改成功")
                        pwd_status = "改密成功"
                    effective_password = GOOGLE_NEW_PASSWORD

                    # 步骤3: 复用已登录的 page 接着登录 Claude
                    session_key = await claude_login_after_google(
                        context, page, email, effective_password, totp_secret
                    )
                    # 登录态落盘复用（改密后的会话仍有效）
                    await save_google_session(context, email)
                    if session_key:
                        logger.info(f"[{idx}/{len(lines)}] {email}: Claude 登录成功")
                        results.append({
                            "email": email, "password": effective_password,
                            "session_key": session_key, "status": "成功", "pwd": pwd_status,
                        })
                        # 追加到 session.txt
                        with open("session.txt", "a") as f:
                            f.write(f"{email}----{effective_password}----{session_key}\n")
                    else:
                        logger.warning(f"[{idx}/{len(lines)}] {email}: 未获取到 sessionKey")
                        results.append({"email": email, "status": f"未获取到sessionKey（{pwd_status}）"})
                except Exception as e:
                    logger.warning(f"[{idx}/{len(lines)}] {email}: 失败 - {e}")
                    results.append({"email": email, "status": f"失败: {e}"})
                finally:
                    await context.close()
        finally:
            # 打印汇总
            print("\n" + "=" * 60)
            print("批量『改密 + 登录 Claude』结果汇总")
            print("=" * 60)
            success = [r for r in results if r["status"] == "成功"]
            failed = [r for r in results if r["status"] != "成功"]
            print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
            if success:
                print(f"\n--- 成功账号 ({len(success)}) ---")
                for r in success:
                    print(f"  {r['email']}  ({r.get('pwd', '')})")
            if failed:
                print(f"\n--- 失败账号 ({len(failed)}) ---")
                for r in failed:
                    print(f"  {r['email']}  ({r['status']})")
            print("=" * 60)
    return
