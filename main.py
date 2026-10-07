#!/usr/bin/env python3.12
"""入口：命令行 mode 分发"""

import asyncio
import email as email_pkg
import imaplib
import logging
import os
import re
import sys
from email.header import decode_header as _decode_header

# camoufox 0.5.x 依赖 Python >=3.10，请用 python3.12 运行（见 run.sh）
if sys.version_info < (3, 10):
    sys.exit(
        f"需要 Python >= 3.10（camoufox 0.5.x 要求），当前为 "
        f"{sys.version_info.major}.{sys.version_info.minor}。"
        f"请用 python3.12 运行，例如：./run.sh 或 python3.12 main.py"
    )

from app.modes import aws as aws_modes
from app.modes import browser as browser_modes
from app.modes import claude as claude_modes
from app.modes import google as google_modes
from app.modes import kiro as kiro_modes
from app.modes import mxroute as mxroute_modes
from app.modes import openai as openai_modes
from app.modes import remote as remote_modes
from app.modes import single as single_modes
from app.modes import subus as subus_modes
from app.modes import text as text_modes
from app.modes.help import print_help
from app.core.imap import imap_delete_uid

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

MODES = ("password", "claude", "password-claude", "session", "batch", "extract", "suspend", "diff",
         "tokens", "refresh", "remote", "kiro", "kiro-apikey", "format", "export-kiro",
         "import-kiro", "aws", "aws-diag", "aws-quota", "aws-extract",
         "aws-claude", "aws-kiro", "aws-kiro-bind", "aws-newapi",
         "subus", "oauth", "bedrock", "overage", "openai", "chrome", "yahoo", "email",
         "claude-mail", "claude-email", "claude-bind", "chatgpt-mail", "emails", "disabled", "common")

# 全量 mode -> handler；claude/aws/kiro/password 仅文件批量时走这里，否则落到单条流程
FILE_ONLY = {"claude": claude_modes.run_claude_batch,
             "password-claude": claude_modes.run_password_claude_batch,
             "aws": aws_modes.run_aws_batch,
             "kiro": kiro_modes.run_kiro_batch,
             "password": google_modes.run_password_batch}
HANDLERS = {"oauth": subus_modes.run_oauth,
            "openai": openai_modes.run_openai,
            "subus": subus_modes.run_subus,
            "bedrock": subus_modes.run_bedrock,
            "aws-diag": aws_modes.run_aws_diag,
            "aws-quota": aws_modes.run_aws_quota,
            "aws-extract": aws_modes.run_aws_extract,
            "aws-claude": aws_modes.run_aws_claude,
            "aws-kiro": aws_modes.run_aws_kiro,
            "aws-kiro-bind": aws_modes.run_aws_kiro_bind,
            "aws-newapi": aws_modes.run_aws_newapi,
            "format": text_modes.run_format,
            "remote": remote_modes.run_remote,
            "diff": text_modes.run_diff,
            "suspend": text_modes.run_suspend,
            "extract": text_modes.run_extract,
            "emails": text_modes.run_emails,
            "tokens": text_modes.run_tokens,
            "overage": kiro_modes.run_overage,
            "kiro-apikey": kiro_modes.run_kiro_apikey,
            "refresh": kiro_modes.run_refresh,
            "export-kiro": kiro_modes.run_export_kiro,
            "import-kiro": kiro_modes.run_import_kiro,
            "batch": claude_modes.run_batch,
            "email": mxroute_modes.run_email,
            "chrome": browser_modes.run_chrome,
            "claude-mail": browser_modes.run_claude_mail,
            "claude-email": browser_modes.run_claude_email,
            "claude-bind": browser_modes.run_claude_email,
            "chatgpt-mail": browser_modes.run_chatgpt_mail,
            "yahoo": lambda mode, raw, is_file: asyncio.get_event_loop().run_in_executor(None, yahoo_imap_inbox, raw),
            "disabled": text_modes.run_disabled,
            "common": text_modes.run_common}


def _decode_mime_header(raw: str) -> str:
    """解码 MIME 编码的邮件头（Subject / From 等）"""
    parts = []
    for fragment, charset in _decode_header(raw):
        if isinstance(fragment, bytes):
            parts.append(fragment.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(fragment)
    return "".join(parts)


def _extract_body(msg) -> str:
    """从 email.message.Message 里提取正文（优先 text/html，其次 text/plain）"""
    if msg.is_multipart():
        html = ""
        text = ""
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


def _extract_claude_link(body: str) -> str:
    """从邮件正文中提取 Claude(claude.ai/anthropic.com) 或 ChatGPT(openai.com/chatgpt.com) 登录链接"""
    url_re = re.compile(
        r"https://(?:[a-zA-Z0-9_-]+\.)*(?:claude\.ai|claude\.com|anthropic\.com|openai\.com|chatgpt\.com)/[^\s\"'<>]+",
        re.IGNORECASE,
    )
    static_re = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|otf|ttf|woff2?|eot)(\?|$)", re.IGNORECASE)
    assets_re = re.compile(r"^https://assets\.", re.IGNORECASE)
    tracker_re = re.compile(r"^https://[^/]*(?:mail\.anthropic\.com|(?:email|mail|url\d*|t|links?|click)\.openai\.com)/", re.IGNORECASE)
    login_kw = re.compile(r"(sign[-_]?in|magic|verify|auth|login|token|invite|onboard)", re.IGNORECASE)
    matches = url_re.findall(body)
    candidates = [
        u for u in matches
        if not static_re.search(u) and not assets_re.match(u) and not tracker_re.match(u)
    ]
    if not candidates:
        return ""
    preferred = [u for u in candidates if login_kw.search(u)]
    return preferred[0] if preferred else candidates[0]


def yahoo_imap_inbox(account_line: str):
    """登录 Yahoo IMAP4 收件箱，从最新的 Anthropic/OpenAI 邮件中提取 Claude/ChatGPT 登录链接。
    account_line 格式: email----app_password
    默认提取到链接后删除该邮件，加 --keep 保留。
    """
    delete = "--keep" not in sys.argv[3:]
    if "----" not in account_line:
        print("账号格式错误，需要: email----app_password")
        return

    email_addr, app_password = account_line.split("----", 1)
    host = "imap.mail.yahoo.com"
    port = 993

    print(f"正在连接 Yahoo IMAP: {host}:{port} ...")
    print(f"账号: {email_addr}")

    try:
        with imaplib.IMAP4_SSL(host, port, timeout=30) as imap:
            imap.login(email_addr, app_password)
            print("登录成功！\n")

            imap.select("INBOX")
            # 同时匹配 Anthropic/Claude 与 OpenAI/ChatGPT 发件人
            typ, data = imap.uid(
                "search", None, 'OR FROM "anthropic" OR FROM "openai" OR FROM "claude" FROM "chatgpt"')
            ids = data[0].split() if data and data[0] else []
            if not ids:
                print("未找到 Anthropic/OpenAI 邮件。")
                imap.logout()
                return

            print(f"找到 {len(ids)} 封 Anthropic/OpenAI 邮件，读取最新一封...\n")

            uid = ids[-1]
            typ, msg_data = imap.uid("fetch", uid, "(RFC822)")
            if typ != "OK" or not msg_data or not msg_data[0]:
                print("读取邮件失败。")
                imap.logout()
                return

            msg = email_pkg.message_from_bytes(msg_data[0][1])
            subject = _decode_mime_header(msg.get("Subject", "(无主题)"))
            from_addr = _decode_mime_header(msg.get("From", ""))
            date = msg.get("Date", "")

            print(f"日期: {date}")
            print(f"发件人: {from_addr}")
            print(f"主题: {subject}\n")

            body = _extract_body(msg)
            link = _extract_claude_link(body)

            if link:
                print(f"登录链接:\n{link}")
                if delete and imap_delete_uid(imap, uid):
                    print("\n已删除该邮件")
            else:
                print("未在邮件中找到 Claude/ChatGPT 登录链接。")

            imap.logout()

    except imaplib.IMAP4.error as e:
        print(f"IMAP 登录失败: {e}")
    except Exception as e:
        print(f"连接异常: {e}")


async def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print_help()
        exit(0)

    # 兼容旧用法：只传一个参数时默认 password 模式；
    # 但若该参数本身是已知 mode 名（如 email），视为该 mode 且无输入，交由其打印用法
    if len(sys.argv) == 2:
        if sys.argv[1] in MODES:
            mode, raw_input = sys.argv[1], ""
        else:
            mode, raw_input = "password", sys.argv[1]
    else:
        mode, raw_input = sys.argv[1], sys.argv[2]

    if mode not in MODES:
        print(f"未知模式: {mode}，请使用 " + " / ".join(MODES))
        exit(1)

    # 判断参数是文件路径还是单条记录
    is_file = os.path.isfile(raw_input)

    handler = HANDLERS.get(mode)
    if handler is None and is_file:
        handler = FILE_ONLY.get(mode)
    if handler is None:
        handler = single_modes.run_single  # 单条记录模式
    await handler(mode, raw_input, is_file)


if __name__ == "__main__":
    asyncio.run(main())
