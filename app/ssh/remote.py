"""SSH 远程：上传脚本、远程执行、批量授权（由 main.py 拆分而来）"""

import asyncio
import logging
import os
import re
import shlex
import subprocess
import threading

from app.settings import SSH_KEY, SSH_USER
from app.core.browser import cloak_browser_session, screenshot_path

logger = logging.getLogger(__name__)


def parse_ssh_server(server_str: str) -> tuple[str, int]:
    """解析 SSH 服务器地址，返回 (user@host, port)"""
    server_str = server_str.strip()
    if ":" in server_str:
        host_part, port_str = server_str.rsplit(":", 1)
        try:
            port = int(port_str)
            return host_part, port
        except ValueError:
            pass
    return server_str, 22


SCRIPT_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def resolve_key_path(ssh_key: str = "") -> str:
    """解析 SSH 私钥路径：支持绝对路径、~ 开头、相对路径（基于脚本目录）"""
    raw = ssh_key or SSH_KEY
    path = os.path.expanduser(raw)
    if not os.path.isabs(path):
        path = os.path.join(SCRIPT_BASE_DIR, path)
    if not os.path.isfile(path):
        raise FileNotFoundError(f"SSH 私钥不存在: {path}，请在 config.py 中配置 SSH_KEY")
    return path


def build_ssh_base(server: str, ssh_key: str = "") -> list[str]:
    """构建 SSH 基础命令参数，使用指定私钥，默认 root 用户"""
    host, port = parse_ssh_server(server)
    if "@" not in host:
        host = f"{SSH_USER}@{host}"

    key_path = resolve_key_path(ssh_key)

    ssh_args = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "PasswordAuthentication=no",
        "-i", key_path,
    ]
    if port != 22:
        ssh_args += ["-p", str(port)]
    ssh_args.append(host)
    return ssh_args


def scp_upload(server: str, local_path: str, remote_path: str, ssh_key: str = "") -> bool:
    """通过 SCP 将本地文件上传到远程服务器"""
    host, port = parse_ssh_server(server)
    if "@" not in host:
        host = f"{SSH_USER}@{host}"

    key_path = resolve_key_path(ssh_key)
    scp_args = [
        "scp",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=10",
        "-o", "PasswordAuthentication=no",
        "-i", key_path,
    ]
    if port != 22:
        scp_args += ["-P", str(port)]
    scp_args += [local_path, f"{host}:{remote_path}"]

    logger.info(f"SCP 上传: {local_path} -> {host}:{remote_path}")
    try:
        result = subprocess.run(scp_args, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            logger.info(f"上传成功: {host}:{remote_path}")
            return True
        else:
            logger.warning(f"上传失败: {result.stderr.strip()}")
            return False
    except Exception as e:
        logger.warning(f"上传异常: {e}")
        return False


def build_remote_cmd(action: str, script_path: str, claude_config_dir: str = "",
                     prompt: str = "", interval: int = 300, loop_count: int = 0,
                     concurrency: int = 1) -> str:
    """构建远程执行的命令字符串"""
    cfg_flag = f" --claude-config-dir {claude_config_dir}" if claude_config_dir else ""

    if action == "auth":
        # 直接执行 claude，首次运行会触发 OAuth 授权流程
        if claude_config_dir:
            return f"CLAUDE_CONFIG_DIR={claude_config_dir} claude"
        else:
            return "claude"
    elif action == "start":
        return (f"bash {script_path}{cfg_flag} start {shlex.quote(prompt)} "
                f"{interval} {loop_count} {concurrency}")
    elif action == "log":
        return f"bash {script_path}{cfg_flag} log -f"
    else:
        # stop / status / check-all
        return f"bash {script_path}{cfg_flag} {action}"


def run_ssh_command(server: str, action: str, script_path: str,
                    claude_config_dir: str = "", ssh_key: str = "",
                    prompt: str = "", interval: int = 300, loop_count: int = 0,
                    concurrency: int = 1) -> dict:
    """SSH 到远程服务器执行命令（非交互式）"""
    remote_cmd = build_remote_cmd(action, script_path, claude_config_dir,
                                  prompt, interval, loop_count, concurrency)
    ssh_args = build_ssh_base(server, ssh_key)
    ssh_args.append(remote_cmd)

    logger.info(f"SSH 执行: {server} -> {remote_cmd}")

    try:
        result = subprocess.run(ssh_args, capture_output=True, text=True, timeout=30)
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode == 0:
            logger.info(f"[{server}] 成功: {stdout}")
            return {"server": server, "status": "成功", "output": stdout}
        else:
            logger.warning(f"[{server}] 失败 (exit {result.returncode}): {stderr or stdout}")
            return {"server": server, "status": f"失败 (exit {result.returncode})", "output": stderr or stdout}
    except subprocess.TimeoutExpired:
        logger.warning(f"[{server}] SSH 连接超时")
        return {"server": server, "status": "超时", "output": "SSH 连接超时 (30s)"}
    except Exception as e:
        logger.warning(f"[{server}] 异常: {e}")
        return {"server": server, "status": f"异常: {e}", "output": ""}


def run_ssh_interactive(server: str, action: str, script_path: str,
                        claude_config_dir: str = "", ssh_key: str = "",
                        prompt: str = "", interval: int = 300, loop_count: int = 0,
                        concurrency: int = 1):
    """SSH 到远程服务器执行交互式命令（log -f 等），直通 stdin/stdout"""
    remote_cmd = build_remote_cmd(action, script_path, claude_config_dir,
                                  prompt, interval, loop_count, concurrency)
    ssh_args = build_ssh_base(server, ssh_key)
    ssh_args.append(remote_cmd)

    logger.info(f"SSH 交互: {server} -> {remote_cmd}")
    print(f"\n{'=' * 60}")
    print(f"连接到 {server}，执行: {remote_cmd}")
    print(f"{'=' * 60}\n")

    try:
        result = subprocess.run(ssh_args)
        return result.returncode
    except KeyboardInterrupt:
        print("\n已中断")
        return 130


class SessionLoginError(Exception):
    """sessionKey 登录 claude.ai 失败（无效/过期，被重定向到登录页）。"""


async def open_auth_url_and_get_code(auth_url: str, session_key: str,
                                     tag: str = None,
                                     raise_on_login_fail: bool = False) -> str:
    """用 sessionKey 登录 claude.ai，打开授权链接，获取返回的 code。

    tag 用作截图命名空间（推荐传 SSH server 名），便于多机调试时区分。
    raise_on_login_fail=True 时，sessionKey 登录失败会抛 SessionLoginError（用于批量时明确跳过后续步骤）；
    默认 False 保持旧行为（登录失败返回 None）。
    """
    async with cloak_browser_session() as browser:
        context = await browser.new_context()
        try:
            # 设置 sessionKey cookie（同时覆盖 .claude.ai 和 .claude.com）
            for domain in [".claude.ai", ".claude.com"]:
                await context.add_cookies([{
                    "name": "sessionKey",
                    "value": session_key,
                    "domain": domain,
                    "path": "/",
                    "httpOnly": True,
                    "secure": True,
                    "sameSite": "Lax",
                }])

            page = await context.new_page()

            # 先访问 claude.ai 确认 sessionKey 有效
            logger.info("验证 sessionKey 登录状态...")
            try:
                await page.goto("https://claude.ai", wait_until="domcontentloaded", timeout=15000)
                await page.wait_for_timeout(3000)
                current_url = page.url
                if "login" in current_url:
                    logger.warning(f"sessionKey 无效，被重定向到登录页: {current_url}")
                    if raise_on_login_fail:
                        raise SessionLoginError(current_url)
                    return None
                logger.info(f"sessionKey 验证通过，当前页面: {current_url}")
            except SessionLoginError:
                raise
            except Exception as e:
                logger.warning(f"验证 sessionKey 失败: {e}")

            # 打开授权链接
            logger.info(f"浏览器打开授权链接: {auth_url}")
            try:
                await page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                logger.warning(f"页面加载异常（可能正常）: {e}")

            await page.wait_for_timeout(3000)

            # 尝试截图记录
            try:
                await page.screenshot(path=screenshot_path("auth_page", tag))
            except Exception:
                pass

            # 尝试点击授权/允许按钮（如果有的话）
            # 注意：claude.ai 会按账号语言本地化按钮文案，需覆盖多语言；
            #       同时严禁点到"拒绝"按钮（Rechazar/Reject/拒绝/Refuser 等）
            clicked = False
            for selector in [
                'button:has-text("Allow")',
                'button:has-text("允许")',
                'button:has-text("Approve")',
                'button:has-text("Authorize")',
                'button:has-text("Accept")',
                'button:has-text("Log in")',
                # 西班牙语（Autorizar / Permitir / Aceptar / Continuar）
                'button:has-text("Autorizar")',
                'button:has-text("Permitir")',
                'button:has-text("Aceptar")',
                'button:has-text("Continuar")',
                # 葡萄牙语
                'button:has-text("Autorizar e continuar")',
                # 法语 / 德语
                'button:has-text("Autoriser")',
                'button:has-text("Genehmigen")',
                'button:has-text("Zulassen")',
                # 日语 / 韩语
                'button:has-text("許可")',
                'button:has-text("承認")',
                'button:has-text("허용")',
                # 英文兜底（放最后，避免与"Don\'t allow"等冲突时优先匹配上面更精确的）
                'button:has-text("Continue")',
                'button:has-text("继续")',
            ]:
                try:
                    btn = page.locator(selector)
                    if await btn.count() > 0 and await btn.first.is_visible():
                        logger.info(f"点击授权按钮: {selector}")
                        await btn.first.click()
                        await page.wait_for_timeout(3000)
                        clicked = True
                        break
                except Exception:
                    continue

            # 兜底：没匹配到任何本地化文案时，点页面里第一个非"拒绝"按钮。
            # 同意页通常只有两个按钮：授权（深色主按钮）+ 拒绝（次按钮），
            # 拒绝类文案统一排除，剩下的就是授权按钮。
            if not clicked:
                reject_words = ["rechazar", "reject", "deny", "don't allow", "dont allow",
                                "cancel", "cancelar", "拒绝", "拒否", "refuser", "ablehnen", "거부"]
                try:
                    buttons = page.locator("button")
                    n = await buttons.count()
                    for i in range(n):
                        b = buttons.nth(i)
                        try:
                            if not await b.is_visible():
                                continue
                            label = ((await b.inner_text()) or "").strip()
                            if not label:
                                continue
                            if any(w in label.lower() for w in reject_words):
                                continue
                            logger.info(f"兜底点击疑似授权按钮: {label!r}")
                            await b.click()
                            await page.wait_for_timeout(3000)
                            clicked = True
                            break
                        except Exception:
                            continue
                except Exception:
                    pass

            try:
                await page.screenshot(path=screenshot_path("auth_after_click", tag))
            except Exception:
                pass

            # 等待页面更新，提取 Authentication Code
            # 页面结构: 标题 "Authentication Code" + 提示 "Paste this into Claude Code:" + input 框
            code = None

            for attempt in range(10):
                await page.wait_for_timeout(2000)

                # 方法1 (优先): 从 input 元素获取完整值
                for sel in ['input[readonly]', 'input[type="text"]', 'input']:
                    try:
                        el = page.locator(sel)
                        if await el.count() > 0:
                            val = await el.first.input_value()
                            val = val.strip()
                            if val and len(val) >= 20:
                                code = val
                                logger.info(f"从 input 元素提取到 code ({len(code)} 字符)")
                                break
                    except Exception:
                        continue

                if code:
                    break

                # 方法2: 从 code/pre 等元素获取
                for sel in ['code', 'pre', '.code', '[data-testid*="code"]', '[class*="code"]']:
                    try:
                        el = page.locator(sel)
                        if await el.count() > 0:
                            val = await el.first.inner_text()
                            val = val.strip()
                            if val and len(val) >= 20:
                                code = val
                                logger.info(f"从元素 {sel} 提取到 code ({len(code)} 字符)")
                                break
                    except Exception:
                        continue

                if code:
                    break

                # 方法3: 从页面文本中按 "Paste this into Claude Code:" 后面的内容提取
                try:
                    page_text = await page.inner_text("body")
                    m = re.search(r'Paste this into Claude Code:\s*(\S+)', page_text)
                    if m:
                        code = m.group(1).strip()
                        logger.info(f"从页面文本提取到 code ({len(code)} 字符)")
                        break
                except Exception:
                    pass

                logger.debug(f"等待 code 出现... ({(attempt+1)*2}s)")

            if not code:
                # 最后兜底：打印页面内容让用户手动查看
                logger.warning("未能自动提取 code，页面内容:")
                try:
                    body_text = await page.inner_text("body")
                    print(body_text[:2000])
                except Exception:
                    pass
                try:
                    no_code_path = screenshot_path("auth_no_code", tag)
                    await page.screenshot(path=no_code_path)
                    logger.info(f"已保存截图到 {no_code_path}")
                except Exception:
                    pass

            return code

        finally:
            await context.close()


async def run_ssh_auth(server: str, claude_config_dir: str, session_key: str,
                       ssh_key: str = "") -> dict:
    """自动化 SSH auth 流程（PTY 交互模式）：
    1. SSH -tt 运行 claude（强制分配 PTY，交互式）
    2. 从输出中提取授权链接
    3. 本地浏览器用 sessionKey 打开链接获取 code
    4. 通过 PTY stdin 将 code 发送给 claude
    """
    import pty
    import select

    remote_cmd = build_remote_cmd("auth", "", claude_config_dir)
    ssh_args = build_ssh_base(server, ssh_key)
    # 插入 -tt 强制分配 PTY，放在 ssh 命令之后、host 之前
    ssh_args.insert(1, "-tt")
    ssh_args.append(remote_cmd)

    logger.info(f"SSH auth (PTY): {server} -> {remote_cmd}")

    # 用 pty 创建伪终端，让 claude 认为在真正的终端中运行
    master_fd, slave_fd = pty.openpty()

    proc = subprocess.Popen(
        ssh_args,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
    )
    os.close(slave_fd)  # 父进程关闭 slave 端

    all_lines = []
    auth_url = None
    auth_url_event = threading.Event()
    trust_confirmed = False
    buffer = ""

    def read_pty_output():
        nonlocal auth_url, trust_confirmed, buffer
        while True:
            try:
                ready, _, _ = select.select([master_fd], [], [], 1.0)
                if not ready:
                    if proc.poll() is not None:
                        break
                    continue
                data = os.read(master_fd, 4096)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                buffer += text

                # 检测信任目录确认提示（可能不以换行结尾）
                # 匹配 "Yes, I trust this folder" 或 "Enter to confirm"
                clean_buffer = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b\[.*?[a-zA-Z]', '', buffer)
                if not trust_confirmed and ("trust" in clean_buffer.lower() and "enter" in clean_buffer.lower()):
                    trust_confirmed = True
                    logger.info("检测到信任目录提示，自动按回车确认...")
                    try:
                        os.write(master_fd, b"\n")
                    except OSError:
                        pass

                # 按行处理
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    # 去除 ANSI 转义序列
                    clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07|\x1b\[.*?[a-zA-Z]', '', line).strip()
                    if not clean_line:
                        continue
                    all_lines.append(clean_line)
                    print(f"  [SSH] {clean_line}")
                    # 搜索授权链接
                    if not auth_url:
                        url_match = re.search(r'(https://\S+)', clean_line)
                        if url_match:
                            url = url_match.group(1)
                            if "oauth" in url or "claude" in url:
                                auth_url = url
                                logger.info(f"捕获到授权链接 ({len(url)} 字符)")
                                auth_url_event.set()
            except OSError:
                break

    reader_thread = threading.Thread(target=read_pty_output, daemon=True)
    reader_thread.start()

    logger.info("等待 claude 输出授权链接...")
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, auth_url_event.wait, 120)

    if not auth_url:
        logger.warning("未能捕获到授权链接")
        proc.terminate()
        reader_thread.join(timeout=5)
        try:
            os.close(master_fd)
        except OSError:
            pass
        full_output = "\n".join(all_lines)
        return {"server": server, "status": "失败", "output": f"未找到授权链接。输出:\n{full_output[:500]}"}

    # 用浏览器打开授权链接获取 code
    logger.info("启动浏览器获取授权 code...")
    code = await open_auth_url_and_get_code(auth_url, session_key, tag=server)

    if not code:
        logger.error("获取授权 code 失败（sessionKey 可能无效或已过期）")
        proc.terminate()
        reader_thread.join(timeout=5)
        try:
            os.close(master_fd)
        except OSError:
            pass
        return {"server": server, "status": "失败", "output": "sessionKey 无效或已过期，无法获取授权 code"}

    logger.info(f"发送 code 到远程 claude CLI ({len(code)} 字符)")
    try:
        os.write(master_fd, (code + "\n").encode())
    except Exception as e:
        logger.warning(f"发送 code 失败: {e}")
        proc.terminate()
        reader_thread.join(timeout=5)
        try:
            os.close(master_fd)
        except OSError:
            pass
        return {"server": server, "status": "失败", "output": f"发送 code 失败: {e}"}

    # 等待 claude 完成授权
    try:
        await loop.run_in_executor(None, proc.wait, 30)
    except subprocess.TimeoutExpired:
        proc.terminate()

    reader_thread.join(timeout=5)
    try:
        os.close(master_fd)
    except OSError:
        pass
    full_output = "\n".join(all_lines)

    if proc.returncode == 0:
        logger.info(f"[{server}] 授权成功！")
        return {"server": server, "status": "成功", "output": "授权完成"}
    else:
        if any(kw in full_output.lower() for kw in ("success", "authenticated", "logged in")):
            logger.info(f"[{server}] 授权成功（从输出判断）！")
            return {"server": server, "status": "成功", "output": "授权完成"}
        return {"server": server, "status": f"退出码 {proc.returncode}", "output": full_output[-500:]}


async def batch_ssh_remote(servers: list[str], action: str, script_path: str,
                           claude_config_dir: str = "", ssh_key: str = "",
                           prompt: str = "", interval: int = 300, loop_count: int = 0,
                           concurrency: int = 1, session_key: str = ""):
    """批量 SSH 到多台服务器执行命令"""

    # 需要脚本的操作，先上传 repeat_claude.sh 到每台服务器
    needs_script = action in ("start", "stop", "status", "log", "check-all")
    if needs_script:
        local_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "repeat_claude.sh")
        if not os.path.isfile(local_script):
            print(f"错误: 本地脚本不存在: {local_script}")
            return
        logger.info(f"上传脚本到 {len(servers)} 台服务器: {local_script} -> {script_path}")
        for server in servers:
            server = server.strip()
            if not server or server.startswith("#"):
                continue
            if not scp_upload(server, local_script, script_path, ssh_key):
                logger.warning(f"[{server}] 脚本上传失败，后续执行可能出错")

    # auth 模式：自动化授权流程
    if action == "auth":
        if not session_key:
            logger.error("auth 模式需要提供 sessionKey 参数")
            print("错误: auth 需要 sessionKey，用法:")
            print("  python main.py remote user@host -d ~/.claude1 auth sk-ant-xxx")
            print("  python main.py remote user@host -d ~/.claude1 auth session.txt")
            return

        results = []
        for idx, server in enumerate(servers, 1):
            server = server.strip()
            if not server or server.startswith("#"):
                continue
            logger.info(f"[{idx}/{len(servers)}] 授权: {server}")
            r = await run_ssh_auth(server, claude_config_dir, session_key, ssh_key)
            results.append(r)

        # 汇总
        print("\n" + "=" * 60)
        print("SSH 授权结果汇总")
        print("=" * 60)
        success = [r for r in results if r["status"] == "成功"]
        failed = [r for r in results if r["status"] != "成功"]
        print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
        if success:
            print(f"\n--- 成功 ({len(success)}) ---")
            for r in success:
                print(f"  {r['server']}: {r['output']}")
        if failed:
            print(f"\n--- 失败 ({len(failed)}) ---")
            for r in failed:
                print(f"  {r['server']}: {r['status']} - {r['output']}")
        print("=" * 60)
        return results

    # log 模式：交互式逐台执行
    if action == "log":
        for idx, server in enumerate(servers, 1):
            server = server.strip()
            if not server or server.startswith("#"):
                continue
            logger.info(f"[{idx}/{len(servers)}] 交互式连接: {server}")
            run_ssh_interactive(server, action, script_path, claude_config_dir,
                                ssh_key, prompt, interval, loop_count, concurrency)
            if idx < len(servers):
                try:
                    input(f"\n按回车继续下一台服务器 ({idx}/{len(servers)})...")
                except KeyboardInterrupt:
                    print("\n已中断批量操作")
                    return
        return

    # 非交互式：批量执行并汇总
    results = []
    for idx, server in enumerate(servers, 1):
        server = server.strip()
        if not server or server.startswith("#"):
            continue
        logger.info(f"[{idx}/{len(servers)}] 处理服务器: {server}")
        r = run_ssh_command(server, action, script_path, claude_config_dir,
                            ssh_key, prompt, interval, loop_count, concurrency)
        results.append(r)

    # 汇总
    print("\n" + "=" * 60)
    print(f"SSH 远程执行结果汇总 (action: {action})")
    print("=" * 60)

    success = [r for r in results if r["status"] == "成功"]
    failed = [r for r in results if r["status"] != "成功"]
    print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")

    if success:
        print(f"\n--- 成功 ({len(success)}) ---")
        for r in success:
            print(f"  {r['server']}: {r['output']}")

    if failed:
        print(f"\n--- 失败 ({len(failed)}) ---")
        for r in failed:
            print(f"  {r['server']}: {r['status']} - {r['output']}")

    print("=" * 60)
    return results


