"""单条记录模式：password / claude / session / aws / kiro 的交互式单账号流程"""

import logging
import os
import sys

from app.accounts.aws import login_aws
from app.accounts.claude import (
    claude_login_after_google,
    login_claude_by_cookies,
    login_claude_by_session,
    register_claude,
)
from app.accounts.google_auth import change_password, google_login
from app.core.browser import (
    aws_session_state_path,
    cloak_browser_session,
    google_session_state_path,
    new_window_sized_context,
    save_aws_session,
    save_google_session,
    screenshot_path,
)
from app.core.parsing import (
    looks_like_cookie_jar,
    parse_aws_input,
    parse_cookie_jar,
    parse_input,
    parse_session_input,
)
from app.kiro.api import kiro_ensure_overage
from app.kiro.parsing import parse_kiro_input, parse_overage_flag
from app.kiro.register import register_kiro
from app.settings import GOOGLE_NEW_PASSWORD

logger = logging.getLogger(__name__)


# 单条记录模式
async def run_single(mode: str, raw_input: str, is_file: bool):
    kiro_parsed = None
    aws_akid = ""
    aws_sak = ""
    session_cookies = None  # cookie 文件（.crash/.json）模式下注入的全部 cookie
    if mode == "session":
        if is_file and looks_like_cookie_jar(raw_input):
            session_key, session_cookies = parse_cookie_jar(raw_input)
            email = os.path.basename(raw_input)
            password = ""
            logger.info(f"从 cookie 文件 {email} 解析到 sessionKey: {session_key[:24]}...（{len(session_cookies)} 条 cookie）")
        else:
            email, password, session_key = parse_session_input(raw_input)
    elif mode == "aws":
        email, password, totp_secret, aws_akid, aws_sak, _region = parse_aws_input(raw_input)
    elif mode == "kiro":
        kiro_parsed = parse_kiro_input(raw_input)
        kmode = kiro_parsed[0]
        if kmode == "builderid":
            _, email, password, totp_secret = kiro_parsed
        elif kmode == "github":
            _, username, password, totp_secret = kiro_parsed
            email = username
        elif kmode == "idc":
            _, start_url, username, temp_pwd, _new_pwd = kiro_parsed
            email = f"{username}@{start_url}"
            password = temp_pwd
            totp_secret = ""
        else:
            raise ValueError(f"未知 kiro mode: {kmode}")
    else:
        email, password, totp_secret = parse_input(raw_input)

    logger.info(f"账号: {email}, 密码: {password}, 模式: {mode}")

    # kiro 单条：register_kiro 内部管 Chrome 生命周期，走独立分支
    if mode == "kiro":
        try:
            overage_action = parse_overage_flag(sys.argv[3:])
        except ValueError as e:
            print(e)
            exit(1)
        try:
            record = await register_kiro(kiro_parsed)
            logger.info(f"Kiro 登录成功: {record.get('email')}  userId={record.get('userId')}")
            if overage_action is not None:
                tag = record.get("email") or email
                if kiro_ensure_overage(record, overage_action):
                    logger.info(f"{tag} overage → {'ENABLED' if overage_action else 'DISABLED'} ✓")
                else:
                    logger.warning(f"{tag} overage 切换失败")
        except Exception as e:
            logger.error(f"执行过程中出错: {e}")
            raise
        return

    # 走到这里的都是 password/claude/password-claude/session/aws 单条——全是给人看的，
    # 统一窗口铺满屏幕可用区、viewport 等于窗口内容区（方便人工查看登录结果）。建 context
    # 的细节（探测可用区 + CDP 收窗口）见 new_window_sized_context。
    # aws 复用 aws storage_state；google 系（password/claude/password-claude）复用 google
    # storage_state —— 跨次跑让 Google 信任本设备，同一浏览器新开 tab 打开 gmail 免重登。
    # 命令行带 --no-session 则强制全新会话。
    google_modes_set = ("password", "claude", "password-claude")
    reuse_session = "--no-session" not in sys.argv[2:] and bool(email) and (
        mode == "aws" or mode in google_modes_set
    )
    if reuse_session and mode == "aws":
        state_path = aws_session_state_path(email)
    elif reuse_session:
        state_path = google_session_state_path(email)
    else:
        state_path = None
    storage_state = state_path if state_path and os.path.exists(state_path) else None

    async with cloak_browser_session(maximized=True) as browser:
        context = await new_window_sized_context(browser, storage_state=storage_state)

        try:
            if mode == "password":
                # 1. 登录 Google
                page = await google_login(context, email, password, totp_secret)

                # 2. 修改密码
                if password == GOOGLE_NEW_PASSWORD:
                    logger.info("传入密码与新密码相同，跳过密码修改")
                else:
                    await change_password(context, page, password, GOOGLE_NEW_PASSWORD, totp_secret)
                logger.info("全部流程完成！密码修改成功！")
                if reuse_session:
                    await save_google_session(context, email)

            elif mode == "claude":
                # 先登录 Google，再打开 claude.ai 获取 sessionKey
                session_key = await register_claude(context, email, password, totp_secret)
                # 登录动作已建立 Google 会话，落盘复用（新开 tab 开 gmail 免重登）
                if reuse_session:
                    await save_google_session(context, email)
                if session_key:
                    logger.info("全部流程完成！Claude 登录成功！")
                    logger.info(f"sessionKey: {session_key}")
                    # 保存到 session.txt（追加模式）
                    with open("session.txt", "a") as f:
                        f.write(f"{email}----{password}----{session_key}\n")
                    logger.info("已保存到 session.txt")
                else:
                    logger.warning("Claude 登录状态不确定或未获取到 sessionKey，请检查截图")

            elif mode == "password-claude":
                # 聚合：登录 Google(仅一次) → 改密 → 复用会话登录 Claude
                page = await google_login(context, email, password, totp_secret)
                if password == GOOGLE_NEW_PASSWORD:
                    logger.info("传入密码与新密码相同，跳过密码修改")
                else:
                    await change_password(context, page, password, GOOGLE_NEW_PASSWORD, totp_secret)
                    logger.info("密码修改成功！")
                effective_password = GOOGLE_NEW_PASSWORD

                session_key = await claude_login_after_google(
                    context, page, email, effective_password, totp_secret
                )
                if reuse_session:
                    await save_google_session(context, email)
                if session_key:
                    logger.info("全部流程完成！改密 + Claude 登录成功！")
                    logger.info(f"sessionKey: {session_key}")
                    with open("session.txt", "a") as f:
                        f.write(f"{email}----{effective_password}----{session_key}\n")
                    logger.info("已保存到 session.txt")
                else:
                    logger.warning("Claude 登录状态不确定或未获取到 sessionKey，请检查截图")

            elif mode == "aws":
                # 仅登录 AWS Root，落 console 首页（Claude Platform 流程走 aws-claude 模式）
                final_url = await login_aws(context, email, password, totp_secret, aws_akid, aws_sak)
                logger.info(f"AWS 登录成功，console: {final_url}")
                if reuse_session:
                    await save_aws_session(context, email)

            elif mode == "session":
                # 通过 sessionKey / cookie 文件登录 Claude
                if session_cookies is not None:
                    status = await login_claude_by_cookies(context, session_cookies)
                else:
                    status = await login_claude_by_session(context, session_key)
                if status.startswith("可用"):
                    logger.info(f"全部流程完成！Claude 登录成功！({status})")
                elif status == "待定":
                    logger.warning("Claude sessionKey 登录待定（challenge 未通过），请检查截图")
                else:
                    logger.warning("Claude sessionKey 登录失败，请检查截图")

        except Exception as e:
            logger.error(f"执行过程中出错: {e}")
            try:
                err_email = email if mode != "session" else None
                for i, pg in enumerate(context.pages):
                    await pg.screenshot(path=screenshot_path(f"error_{i}", err_email))
                logger.info("已保存错误截图到 screenshots/")
            except Exception:
                pass

        # 保持浏览器打开，按回车关闭（仅交互终端，避免 cron / SSH 非交互环境永久挂死）
        if sys.stdin.isatty():
            try:
                input("流程结束，按回车键关闭浏览器...")
            except (EOFError, KeyboardInterrupt):
                pass
        else:
            logger.info("非交互环境，流程结束直接关闭浏览器")
