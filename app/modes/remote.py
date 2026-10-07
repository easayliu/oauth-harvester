"""remote mode：SSH 远程执行 repeat_claude.sh"""

import logging
import os
import re
import sys

from app.core.parsing import parse_session_input
from app.settings import (
    REMOTE_CLAUDE_CONFIG_DIR,
    REMOTE_CONCURRENCY,
    REMOTE_INTERVAL,
    REMOTE_LOOP_COUNT,
    REMOTE_PROMPT,
    REMOTE_SCRIPT_PATH,
    SSH_KEY,
    SSH_SERVERS,
)
from app.ssh.remote import batch_ssh_remote

logger = logging.getLogger(__name__)


# remote 模式：SSH 到远程服务器执行 repeat_claude.sh
async def run_remote(mode: str, raw_input: str, is_file: bool):
    target = raw_input  # user@host 或文件路径

    # 解析 remote 子参数: python main.py remote <target> [-d dir] <action> [prompt] [interval] [loop_count] [concurrency]
    remote_args = sys.argv[3:]
    claude_config_dir = REMOTE_CLAUDE_CONFIG_DIR
    positional = []

    i = 0
    while i < len(remote_args):
        if remote_args[i] in ("-d", "--claude-config-dir"):
            if i + 1 < len(remote_args):
                # -d 是远程路径，如果 shell 把 ~ 展开成了本地 home，还原回 ~
                raw_dir = remote_args[i + 1]
                local_home = os.path.expanduser("~")
                if raw_dir.startswith(local_home + "/") or raw_dir == local_home:
                    raw_dir = "~" + raw_dir[len(local_home):]
                claude_config_dir = raw_dir
                i += 2
            else:
                print("错误: -d 需要指定目录路径")
                exit(1)
        else:
            positional.append(remote_args[i])
            i += 1

    # positional: [action] [session_key_or_prompt] [interval] [loop_count] [concurrency]
    valid_actions = ("auth", "start", "stop", "status", "log", "check-all")
    if positional and positional[0] in valid_actions:
        action = positional[0]
        rest = positional[1:]
    else:
        action = "start"
        rest = positional

    # auth 模式：第一个参数是 sessionKey 或包含 sessionKey 的文件
    session_key_for_auth = ""
    if action == "auth":
        sk_raw = rest[0] if rest else ""
        if sk_raw:
            if os.path.isfile(sk_raw):
                # 从文件中提取第一个 sk-ant key
                with open(sk_raw, "r") as f:
                    for line in f:
                        m = re.search(r"sk-ant-\S+", line)
                        if m:
                            session_key_for_auth = m.group(0)
                            break
                if not session_key_for_auth:
                    print(f"错误: 文件 {sk_raw} 中未找到 sk-ant- 开头的 sessionKey")
                    exit(1)
            elif sk_raw.startswith("sk-ant-"):
                session_key_for_auth = sk_raw
            else:
                # 尝试用 parse_session_input 解析
                try:
                    _, _, session_key_for_auth = parse_session_input(sk_raw)
                except ValueError:
                    print(f"错误: 无法识别 sessionKey: {sk_raw}")
                    exit(1)

    prompt = rest[0] if len(rest) > 0 and action != "auth" else REMOTE_PROMPT
    interval = int(rest[1]) if len(rest) > 1 and action != "auth" else REMOTE_INTERVAL
    loop_count = int(rest[2]) if len(rest) > 2 and action != "auth" else REMOTE_LOOP_COUNT
    concurrency = int(rest[3]) if len(rest) > 3 and action != "auth" else REMOTE_CONCURRENCY

    # 确定服务器列表
    if os.path.isfile(target):
        with open(target, "r") as f:
            servers = [l.strip() for l in f.readlines() if l.strip() and not l.strip().startswith("#")]
    elif target == "config":
        servers = list(SSH_SERVERS)
    else:
        servers = [target]

    if not servers:
        print("错误: 未指定服务器。请传入 user@host、服务器列表文件，或在 config.py 中配置 SSH_SERVERS")
        exit(1)

    logger.info(f"准备 SSH 到 {len(servers)} 台服务器，action={action}"
                 + (f"，claude_config_dir={claude_config_dir}" if claude_config_dir else ""))
    await batch_ssh_remote(servers, action, REMOTE_SCRIPT_PATH, claude_config_dir,
                           SSH_KEY, prompt, interval, loop_count, concurrency,
                           session_key_for_auth)
    return
