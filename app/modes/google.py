"""Google 相关 mode：password 批量改密"""

import logging

from app.accounts.google_auth import change_password, google_login
from app.core.browser import cloak_browser_session
from app.core.parsing import parse_input
from app.settings import GOOGLE_NEW_PASSWORD

logger = logging.getLogger(__name__)


# password 模式：支持文件批量修改密码
async def run_password_batch(mode: str, raw_input: str, is_file: bool):
    with open(raw_input, "r") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    logger.info(f"读取到 {len(lines)} 个账号，开始批量修改密码...")

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

                logger.info(f"[{idx}/{len(lines)}] 修改密码: {email}")
                context = await browser.new_context()
                try:
                    page = await google_login(context, email, password, totp_secret)
                    if password == GOOGLE_NEW_PASSWORD:
                        logger.info(f"[{idx}/{len(lines)}] {email}: 密码已是最新，跳过")
                        results.append({"email": email, "status": "已是最新"})
                    else:
                        await change_password(context, page, password, GOOGLE_NEW_PASSWORD, totp_secret)
                        logger.info(f"[{idx}/{len(lines)}] {email}: 密码修改成功")
                        results.append({"email": email, "status": "成功"})
                except Exception as e:
                    logger.warning(f"[{idx}/{len(lines)}] {email}: 失败 - {e}")
                    results.append({"email": email, "status": f"失败: {e}"})
                finally:
                    await context.close()
        finally:
            # 打印汇总
            print("\n" + "=" * 60)
            print("批量修改密码结果汇总")
            print("=" * 60)
            success = [r for r in results if r["status"] in ("成功", "已是最新")]
            failed = [r for r in results if r["status"] not in ("成功", "已是最新")]
            print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
            if failed:
                print(f"\n--- 失败账号 ({len(failed)}) ---")
                for r in failed:
                    print(f"  {r['email']}  ({r['status']})")
            print("=" * 60)
    return
