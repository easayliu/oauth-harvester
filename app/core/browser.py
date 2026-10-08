"""浏览器/通用工具：CloakBrowser 启动、拟人操作、截图、Cloudflare 等待、TOTP（由 main.py 拆分而来）"""

from collections import namedtuple
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta
import asyncio
import functools
import json
import logging
import os
import platform
import random
import re
import shutil
import subprocess
import tempfile
import time

from playwright.async_api import Page, BrowserContext
from cloakbrowser import launch_async, launch_persistent_context_async

from app.settings import (
    HEADLESS,
    PROXY,
    KIRO_BROWSER_BACKEND,
    BOTBROWSER_EXEC_PATH,
    BOTBROWSER_PROFILE_PATH,
    KIRO_PROFILE_MAX_COUNT,
    KIRO_PROFILE_MIN_FREE_GB,
    KIRO_PROFILE_ACTIVE_TTL_S,
    BROWSER_LOCALE,
    BROWSER_TIMEZONE,
    BROWSER_OS,
    BROWSER_GEOIP,
    PROXY_TEST_URL,
)

logger = logging.getLogger(__name__)


def _proxy_settings(proxy_url: str = None):
    """把代理 URL 解析成 Playwright 标准 ProxySettings dict。

    proxy_url 不传时用 config 的 PROXY；传了（如本地中转的无认证 URL）则用它。

    关键：Playwright / Camoufox 的浏览器内核**不会**从 server URL 的
    `user:pass@host:port` 里读取账号密码 —— 必须拆成独立的 username/password
    字段，否则代理返回 407，Page.goto 直接抛 `<unknown error>`。
    注意：带认证的 socks5 浏览器内核直接不支持（launch 抛 socks5 proxy
    authentication），这种情况应先用 proxy_relay 起本地无认证中转，把中转的
    URL 传进来。

    返回 None 表示未配置代理；无认证时只返回 {"server": ...}。
    """
    url = proxy_url or PROXY
    if not url:
        return None
    from urllib.parse import urlsplit, unquote
    parts = urlsplit(url)
    scheme = parts.scheme or "http"
    # socks5h (remote DNS) 是 curl 约定，Playwright/Chrome 不认；归一化成 socks5
    # （Chrome socks5 默认就走远程 DNS，效果等价 socks5h）
    if scheme == "socks5h":
        scheme = "socks5"
    server = f"{scheme}://{parts.hostname}:{parts.port}" if parts.port else f"{scheme}://{parts.hostname}"
    cfg = {"server": server}
    if parts.username:
        cfg["username"] = unquote(parts.username)
    if parts.password:
        cfg["password"] = unquote(parts.password)
    return cfg


async def _proxy_settings_async(proxy_url: str = None):
    """带本地中转的 _proxy_settings：浏览器内核用。proxy_url 不传时用 config 的 PROXY。

    PROXY 是带认证的 socks5 时，浏览器内核不支持 —— 先用 proxy_relay 起一个本地
    无认证 SOCKS5 中转，把中转 URL（socks5://127.0.0.1:<port>，无账密）交给浏览器，
    真正的认证/远程 DNS 由中转转发到上游完成。其余情况（无代理 / http 代理 /
    无认证 socks）直接走 _proxy_settings()。
    """
    from app.core.proxy_relay import ensure_relay
    url = proxy_url or PROXY
    local = await ensure_relay(url)
    return _proxy_settings(local or url)


def check_proxy(timeout: float = 12.0, proxy_url: str = None):
    """走代理（proxy_url，不传时用 PROXY）请求 PROXY_TEST_URL，返回出口 IP（字符串）；未配代理或失败返回 None。

    做一次轻量自检验证代理可用并打印出口 IP。注意：SOCKS 代理必须把**主机名**
    原样交给代理做远程 DNS（等价 curl 的 socks5h）；若先在本地解析再交 IP，很多
    只认远程 DNS 的代理会直接拒绝。socks:// 需要 PySocks，没装则跳过自检。
    """
    proxy_url = proxy_url or PROXY
    if not proxy_url:
        logger.info("check_proxy: 未配置 PROXY，跳过")
        return None

    import socket as _socket
    import ssl
    from urllib.parse import urlsplit, unquote

    tparts = urlsplit(PROXY_TEST_URL)
    host = tparts.hostname
    port = tparts.port or (443 if tparts.scheme == "https" else 80)
    path = tparts.path or "/"

    pparts = urlsplit(proxy_url)
    scheme = (pparts.scheme or "http").lower()

    try:
        if scheme.startswith("socks"):
            import socks  # PySocks
            sock = socks.socksocket()
            sock.set_proxy(
                socks.SOCKS5 if scheme.startswith("socks5") else socks.SOCKS4,
                pparts.hostname, pparts.port,
                rdns=True,  # 远程 DNS：把主机名交给代理解析，等价 socks5h
                username=unquote(pparts.username) if pparts.username else None,
                password=unquote(pparts.password) if pparts.password else None,
            )
        else:
            # http(s) 代理：urllib ProxyHandler 原生支持（含账号密码），不用手搓 CONNECT
            return _check_proxy_http(timeout, proxy_url)

        sock.settimeout(timeout)
        sock.connect((host, port))  # 主机名交给代理（rdns）
        if tparts.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: proxy-check\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode())
        buf = b""
        while len(buf) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        sock.close()
        body = buf.split(b"\r\n\r\n", 1)[-1].decode(errors="replace").strip()
        ip = body.splitlines()[-1].strip() if body else ""
    except ImportError:
        logger.warning("check_proxy: socks 代理需要 PySocks（pip install pysocks），已跳过自检")
        return None
    except Exception as e:
        logger.warning("check_proxy: 代理不可用（%s）：%s", PROXY_TEST_URL, e)
        return None

    if not ip:
        logger.warning("check_proxy: 请求成功但未解析到 IP（%s）", PROXY_TEST_URL)
        return None
    logger.info("check_proxy: 代理出口 IP = %s（via %s）", ip, PROXY_TEST_URL)
    return ip


def _check_proxy_http(timeout, proxy_url):
    """http(s) 代理分支：用 urllib 的 ProxyHandler（原生支持账号密码）。"""
    import urllib.request
    try:
        handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        opener = urllib.request.build_opener(handler)
        ip = opener.open(PROXY_TEST_URL, timeout=timeout).read().decode().strip()
    except Exception as e:
        logger.warning("check_proxy: 代理不可用（%s）：%s", PROXY_TEST_URL, e)
        return None
    logger.info("check_proxy: 代理出口 IP = %s（via %s）", ip, PROXY_TEST_URL)
    return ip


def _resolve_geoip(eff_geoip, proxy_url: str = None):
    """geoip=True + socks 代理时，自己把出口 IP 先算出来，返回 IP 字符串给 camoufox。

    为什么要插手：camoufox 的 public_ip() 用 requests 走 `socks5://`（本地 DNS）请求
    ipecho.net 等地址；只认远程 DNS 的代理会让这些请求全部超时 → InvalidIP 启动崩溃。
    我们用 check_proxy()（socks5h/远程 DNS）拿到真实出口 IP，以字符串传给 camoufox，
    camoufox 见到字符串就跳过 public_ip() 直接做地理定位（utils.py:737）。

    - eff_geoip 不是 True（已是 IP 串 / False / None）：原样返回，不动。
    - 没配代理 或 http(s) 代理：camoufox 直连没有远程 DNS 问题，返回 True 交给它。
    - 预解析失败：回退 True，交给 camoufox 自己兜底（可能仍超时，但不比现状差）。
    """
    if eff_geoip is not True:
        return eff_geoip
    proxy_url = proxy_url or PROXY
    if not proxy_url:
        return True
    from urllib.parse import urlsplit
    if not (urlsplit(proxy_url).scheme or "").lower().startswith("socks"):
        return True
    ip = check_proxy(proxy_url=proxy_url)
    if ip:
        logger.info("geoip: 预解析出口 IP=%s，绕过 camoufox public_ip（socks 远程 DNS）", ip)
        return ip
    logger.warning("geoip: 预解析出口 IP 失败，回退交给 camoufox public_ip（可能超时）")
    return True


async def _resolve_geoip_async(eff_geoip, proxy_url: str = None):
    """_resolve_geoip 的异步包装：阻塞网络探测丢进 executor，避免卡事件循环。"""
    if eff_geoip is not True:
        return eff_geoip
    return await asyncio.get_event_loop().run_in_executor(None, _resolve_geoip, eff_geoip, proxy_url)


_PLAYWRIGHT_BACKEND = "cloakbrowser"
SCREENSHOT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "screenshots")


def screenshot_path(name: str, email: str = None) -> str:
    """生成命名空间化的截图路径：screenshots/<email|_misc>/<HHMMSS>_<name>.png

    避免多账号批量跑时互相覆盖。会自动创建目录。
    """
    safe_email = re.sub(r"[^a-zA-Z0-9._-]", "_", email) if email else "_misc"
    sub_dir = os.path.join(SCREENSHOT_ROOT, safe_email)
    os.makedirs(sub_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not name.lower().endswith(".png"):
        name = f"{name}.png"
    return os.path.join(sub_dir, f"{ts}_{name}")

async def human_delay(page: Page, action: str = "default"):
    """模拟真人操作的随机延迟"""
    delays = {
        "click":    (800, 2000),    # 点击后等待
        "type":     (1500, 3500),   # 输入后等待
        "navigate": (3000, 6000),   # 页面跳转后等待
        "load":     (2000, 5000),   # 等待加载
        "default":  (1000, 3000),   # 默认
    }
    min_ms, max_ms = delays.get(action, delays["default"])
    ms = random.randint(min_ms, max_ms)
    logger.debug(f"模拟等待 {ms}ms ({action})")
    await page.wait_for_timeout(ms)


async def human_type(page: Page, selector: str, text: str):
    """模拟真人逐字输入，带随机间隔和偶尔的停顿"""
    locator = page.locator(selector)
    await locator.click()
    await page.wait_for_timeout(random.randint(200, 500))

    for i, char in enumerate(text):
        await page.keyboard.type(char, delay=random.randint(50, 180))
        # 偶尔停顿一下，模拟真人思考
        if random.random() < 0.1:
            await page.wait_for_timeout(random.randint(300, 800))


async def human_click(page: Page, selector: str):
    """模拟真人点击：先移动到元素附近，再点击"""
    locator = page.locator(selector)
    box = await locator.bounding_box()
    if box:
        # 在元素范围内随机偏移点击位置
        x = box["x"] + box["width"] * random.uniform(0.3, 0.7)
        y = box["y"] + box["height"] * random.uniform(0.3, 0.7)
        await page.mouse.move(x, y, steps=random.randint(5, 15))
        await page.wait_for_timeout(random.randint(100, 300))
        await page.mouse.click(x, y)
    else:
        await locator.click()


KIRO_PROFILE_ROOT = os.path.expanduser("~/.kiro-profiles")
KIRO_FIREFOX_PROFILE_ROOT = os.path.expanduser("~/.kiro-firefox-profiles")
KIRO_WEBKIT_PROFILE_ROOT = os.path.expanduser("~/.kiro-webkit-profiles")
KIRO_BOTBROWSER_PROFILE_ROOT = os.path.expanduser("~/.kiro-botbrowser-profiles")
KIRO_REALCHROME_PROFILE_ROOT = os.path.expanduser("~/.kiro-realchrome-profiles")

# AWS 系列（aws / aws-claude / aws-kiro）登录会话持久化目录：按 admin 邮箱存一份
# storage_state（cookie + localStorage），下次跑同一账号直接复用、跳过 root 登录。
AWS_SESSION_ROOT = os.path.expanduser("~/.aws-sessions")


def aws_session_state_path(email: str) -> str:
    """按 admin 邮箱生成 storage_state 文件路径（cookie/localStorage 落盘处）。"""
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", email or "_misc")
    os.makedirs(AWS_SESSION_ROOT, exist_ok=True)
    return os.path.join(AWS_SESSION_ROOT, f"{safe}.json")


async def save_aws_session(context: BrowserContext, email: str) -> None:
    """登录成功后把当前 context 的会话（cookie/localStorage）落盘，供下次复用。
    失败仅告警、不影响主流程。"""
    if not email:
        return
    try:
        path = aws_session_state_path(email)
        await context.storage_state(path=path)
        logger.info(f"已保存 AWS 登录会话: {path}")
    except Exception as e:
        logger.warning(f"保存 AWS 登录会话失败（不影响本次）: {e}")


# Google 系列（password / claude / password-claude）登录会话持久化目录：按 Google
# 邮箱存一份 storage_state。复用后 Google 逐渐把这台"设备"当可信设备，同一浏览器
# 里新开 tab 打开 gmail/myaccount 不再被要求重新登录（避开全新无痕指纹=陌生设备的挑战）。
GOOGLE_SESSION_ROOT = os.path.expanduser("~/.google-sessions")


def google_session_state_path(email: str) -> str:
    """按 Google 邮箱生成 storage_state 文件路径（cookie/localStorage 落盘处）。"""
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", email or "_misc")
    os.makedirs(GOOGLE_SESSION_ROOT, exist_ok=True)
    return os.path.join(GOOGLE_SESSION_ROOT, f"{safe}.json")


async def save_google_session(context: BrowserContext, email: str) -> None:
    """登录成功后把当前 context 的会话（cookie/localStorage）落盘，供下次复用。
    失败仅告警、不影响主流程。"""
    if not email:
        return
    try:
        path = google_session_state_path(email)
        await context.storage_state(path=path)
        logger.info(f"已保存 Google 登录会话: {path}")
    except Exception as e:
        logger.warning(f"保存 Google 登录会话失败（不影响本次）: {e}")


def _iter_kiro_profiles(root: str):
    """root 下的账号 profile 目录，返回 [(path, mtime)]。跳过基准缓存 / 隐藏项 / 锁文件
    （名字以 "_" 或 "." 开头的都不是账号 profile）。"""
    out = []
    try:
        names = os.listdir(root)
    except OSError:
        return out
    for name in names:
        if name.startswith("_") or name.startswith("."):
            continue
        p = os.path.join(root, name)
        try:
            if os.path.isdir(p):
                out.append((p, os.path.getmtime(p)))
        except OSError:
            pass
    return out


@contextmanager
def _profile_evict_lock(root: str):
    """串行化同一 root 的 profile 清理：并发批量 / 多 CLI 同跑时避免重复删同一批。"""
    import fcntl
    os.makedirs(root, exist_ok=True)
    f = open(os.path.join(root, ".profile_evict.lock"), "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(f, fcntl.LOCK_UN)
        finally:
            f.close()


def _enforce_kiro_profile_limits(root: str) -> None:
    """按 LRU（最旧 mtime 优先）清理 root 下的 profile，直到同时满足：
      · profile 数 ≤ KIRO_PROFILE_MAX_COUNT
      · 磁盘可用 ≥ KIRO_PROFILE_MIN_FREE_GB
    近 KIRO_PROFILE_ACTIVE_TTL_S 秒内活跃的 profile（可能正被其它进程使用）不删。
    任一上限置 0 即关闭该判据；异常一律吞掉，绝不因清理中断登录。"""
    max_count = KIRO_PROFILE_MAX_COUNT
    min_free = int(KIRO_PROFILE_MIN_FREE_GB * (1024 ** 3))
    if max_count <= 0 and min_free <= 0:
        return
    try:
        with _profile_evict_lock(root):
            profs = _iter_kiro_profiles(root)
            profs.sort(key=lambda x: x[1])  # 最旧在前
            remaining = len(profs)
            now = time.time()

            def _need_evict(count: int) -> bool:
                if 0 < max_count < count:
                    return True
                if min_free > 0:
                    try:
                        if shutil.disk_usage(root).free < min_free:
                            return True
                    except OSError:
                        pass
                return False

            removed = 0
            for path, mtime in profs:
                if not _need_evict(remaining):
                    break
                if now - mtime < KIRO_PROFILE_ACTIVE_TTL_S:
                    continue  # 近期活跃，可能正在跑，跳过
                shutil.rmtree(path, ignore_errors=True)
                remaining -= 1
                removed += 1
            if removed:
                try:
                    free_gb = shutil.disk_usage(root).free / (1024 ** 3)
                except OSError:
                    free_gb = -1
                logger.info(
                    f"kiro profile 清理：{os.path.basename(root)} 删除 {removed} 个最旧 profile"
                    f"（剩 {remaining} 个，磁盘可用 {free_gb:.1f}GB；"
                    f"上限 count={max_count} / free={KIRO_PROFILE_MIN_FREE_GB}GB）")
    except Exception as e:
        logger.debug(f"kiro profile 清理跳过（忽略）: {e}")


def get_kiro_profile_dir(email: str, browser: str = "chrome") -> str:
    """按 email 生成持久化 profile 目录（避免每次"全新设备"指纹触发 Google 风控）。
    新建前按 LRU 清理旧 profile，避免 ~/.kiro-*profiles 无限增长打满磁盘。"""
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", email)
    root = {"firefox": KIRO_FIREFOX_PROFILE_ROOT,
            "webkit": KIRO_WEBKIT_PROFILE_ROOT,
            "botbrowser": KIRO_BOTBROWSER_PROFILE_ROOT,
            "realchrome": KIRO_REALCHROME_PROFILE_ROOT}.get(browser, KIRO_PROFILE_ROOT)
    _enforce_kiro_profile_limits(root)
    path = os.path.join(root, safe)
    os.makedirs(path, exist_ok=True)
    return path


# ============================================================
# Kiro 静态资源缓存共享
# ------------------------------------------------------------
# app.kiro.dev 的前端 chunk（assets.app.kiro.dev）对所有账号是同一份、与账号无关。
# 但 profile 按邮箱隔离，每个新账号都是空缓存，要透过不稳定的代理/CDN 把整套 chunk
# 冷拉一遍，拉失败就落到 "Kiro failed to load" 的 ErrorBoundary 兜底页。
#
# 做法：用一个「从不登录、只打开 signin 页」的基准 profile 预热一次，把它的 cache2/
# 播种进每个新账号 profile。基准从不登录 → cache2 里只有匿名静态资源、不含任何
# authenticated 响应 → 跨账号播种无会话泄漏风险；且只拷 cache2/，绝不碰
# cookies/localStorage/指纹相关文件。预热或播种任何一步失败都安静降级为原来的冷加载。
# ============================================================
KIRO_ASSET_CACHE_BASE = os.path.join(KIRO_FIREFOX_PROFILE_ROOT, "_asset_cache_base")
_ASSET_CACHE_LOCK = os.path.join(KIRO_FIREFOX_PROFILE_ROOT, ".asset_cache.lock")
# cache2 小于此值视为「资源没拉到」（正常预热后有数 MB），不拿来播种/不认为已就绪
_ASSET_CACHE_MIN_BYTES = 1_000_000
# 基准超过此时长就重新预热，跟上 kiro 前端发版换 chunk 哈希
_ASSET_CACHE_MAX_AGE_S = 24 * 3600
_ASSET_PREWARM_URL = "https://app.kiro.dev/signin"


def _dir_size(path: str) -> int:
    """目录内所有文件字节数之和（缺失/不可读的条目直接跳过）。"""
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


@contextmanager
def _asset_cache_lock():
    """跨进程串行化基准缓存的读/写/预热：并发批量或多次 CLI 同时跑时，避免多个
    预热往同一个基准 profile 抢写、或播种时读到写了一半的 cache2。"""
    import fcntl
    os.makedirs(KIRO_FIREFOX_PROFILE_ROOT, exist_ok=True)
    f = open(_ASSET_CACHE_LOCK, "w")
    try:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(f, fcntl.LOCK_UN)
        finally:
            f.close()


def _base_cache_dir() -> str:
    return os.path.join(KIRO_ASSET_CACHE_BASE, "cache2")


def _base_cache_is_healthy() -> bool:
    c = _base_cache_dir()
    return os.path.isdir(c) and _dir_size(c) >= _ASSET_CACHE_MIN_BYTES


def _base_cache_is_fresh() -> bool:
    try:
        return (time.time() - os.path.getmtime(_base_cache_dir())) <= _ASSET_CACHE_MAX_AGE_S
    except OSError:
        return False


def _seed_kiro_asset_cache(profile_dir: str) -> None:
    """【已停用：不复用跨账号缓存】原本把共享基准 cache2/ 播种进新账号 profile 以免冷加载，
    但"一份被 N 个账号共享的字节完全一致的缓存"本身是跨账号关联信号（ETag/缓存条目探测、
    cache-timing 指纹会把这批号识别成同一设备）。现改为每个账号用自己独立的冷缓存、正常启动，
    以速度换风控隔离。保留函数壳避免破坏调用点。"""
    return


def _seed_kiro_asset_cache_disabled(profile_dir: str) -> None:
    try:
        # 基准 profile 自己不播种（它就是缓存源）
        if os.path.abspath(profile_dir) == os.path.abspath(KIRO_ASSET_CACHE_BASE):
            return
        dst = os.path.join(profile_dir, "cache2")
        # profile 已有像样缓存（重跑同账号）→ 用它自己的，别覆盖
        if os.path.isdir(dst) and _dir_size(dst) >= _ASSET_CACHE_MIN_BYTES:
            return
        with _asset_cache_lock():
            src = _base_cache_dir()
            if not (os.path.isdir(src) and _dir_size(src) >= _ASSET_CACHE_MIN_BYTES):
                return  # 基准还没预热成功，安静降级到冷加载
            if os.path.isdir(dst):
                shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst)
        logger.info(
            f"kiro 资源缓存：已从基准播种 cache2 → {os.path.basename(profile_dir)}"
            f"（跳过 assets.app.kiro.dev chunk 冷加载）")
    except Exception as e:
        logger.debug(f"kiro 资源缓存播种跳过（忽略）: {e}")


def _promote_kiro_asset_cache(profile_dir: str) -> None:
    """把一个完整跑通账号的 cache2/ 晋升为共享基准,供后续新账号播种。

    为什么需要:登录不了那步失败在「点 Continue 之后懒加载的路由 chunk」,而「从不登录
    的预热」基准只覆盖 /signin + 组织/Region 的 chunk、盖不到它。只有完整跑通的账号
    profile 才含那个 chunk——拿它当基准,新账号才是真「完整包」、不用再去 assets.app.kiro.dev
    下那个会失败的 chunk。

    覆盖策略:只在「本账号缓存更完整(更大)或基准已过期」时替换,避免用残缺缓存(中途失败的
    账号)把好基准冲掉。只拷 cache2/,不含 cookie/localStorage/账号态。异常一律吞掉。

    【已停用：不复用跨账号缓存】不再把登录过的账号 cache2 发布成共享基准（见
    _seed_kiro_asset_cache 说明）。保留函数壳避免破坏调用点。"""
    return


def _promote_kiro_asset_cache_disabled(profile_dir: str) -> None:
    try:
        if os.path.abspath(profile_dir) == os.path.abspath(KIRO_ASSET_CACHE_BASE):
            return
        src = os.path.join(profile_dir, "cache2")
        if not (os.path.isdir(src) and _dir_size(src) >= _ASSET_CACHE_MIN_BYTES):
            return  # 本账号缓存不完整(可能中途失败),不拿来晋升
        src_size = _dir_size(src)
        with _asset_cache_lock():
            dst = _base_cache_dir()
            base_size = _dir_size(dst) if os.path.isdir(dst) else 0
            # 基准已完整、新鲜、且不比本账号小 → 无需替换
            if base_size >= _ASSET_CACHE_MIN_BYTES and _base_cache_is_fresh() \
                    and base_size >= src_size:
                return
            os.makedirs(KIRO_ASSET_CACHE_BASE, exist_ok=True)
            tmp = dst + ".tmp"
            if os.path.isdir(tmp):
                shutil.rmtree(tmp, ignore_errors=True)
            shutil.copytree(src, tmp)  # 先拷到临时目录,拷崩了也不动现有基准
            if os.path.isdir(dst):
                shutil.rmtree(dst, ignore_errors=True)
            os.replace(tmp, dst)  # 同盘目录原子替换
        logger.info(
            f"kiro 资源缓存：已用完整账号 {os.path.basename(profile_dir)} 的 cache2"
            f"（{src_size // 1024} KB）晋升为基准，后续新账号播种完整包")
    except Exception as e:
        logger.debug(f"kiro 资源缓存晋升跳过（忽略）: {e}")


async def prewarm_kiro_asset_cache() -> None:
    """预热基准 profile：不登录、只打开 signin 页，把 assets.app.kiro.dev 的前端 chunk
    拉进基准 cache2/，供后续每个账号 profile 播种。基准已就绪且新鲜就直接跳过。
    预热失败不抛异常——登录流程照常冷加载，只是少了这层加速。

    整个预热（含浏览器启动）持锁进行：多进程/多次 CLI 同时开工时，只有一个真去预热，
    其余等它结束后看到新鲜基准直接跳过，不会往同一基准 profile 抢写。

    【已停用：不复用跨账号缓存】共享基准已弃用（见 _seed_kiro_asset_cache），预热基准无处可播种，
    故直接跳过这次无用的浏览器启动。保留函数壳避免破坏调用点。"""
    return


async def prewarm_kiro_asset_cache_disabled() -> None:
    try:
        with _asset_cache_lock():
            if _base_cache_is_healthy() and _base_cache_is_fresh():
                logger.info("kiro 资源缓存：基准已就绪且新鲜，跳过预热")
                return
            # 基准过期 → 清掉旧 cache2 拿一份干净的当前快照（避免旧 chunk 哈希堆积）
            if os.path.isdir(_base_cache_dir()) and not _base_cache_is_fresh():
                shutil.rmtree(_base_cache_dir(), ignore_errors=True)
            os.makedirs(KIRO_ASSET_CACHE_BASE, exist_ok=True)

            logger.info("kiro 资源缓存：预热基准 profile（打开 signin 拉前端 chunk，不登录）...")
            context, cm = await launch_camoufox_persistent_context(KIRO_ASSET_CACHE_BASE)
            try:
                page = await context.new_page()
                try:
                    await page.goto(_ASSET_PREWARM_URL, wait_until="load", timeout=60000)
                except Exception as e:
                    logger.debug(f"kiro 资源缓存：预热 goto 异常（继续等 chunk 落盘）: {e}")
                # 观察到冷加载失败点在「选 Your organization → Region 表单」那步的路由 chunk，
                # 光落地 /signin 不一定会拉它。这里复用登录用的入口点击，把 SPA 推进到
                # 组织/Region 表单，逼出同一批懒加载 chunk——但只点入口、不填不提交、不去 AWS，
                # 全程无任何凭据，基准 cache2 仍只含匿名静态资源。点不到就算了，不影响预热。
                try:
                    from app.kiro.register import _kiro_click_signin_option
                    await asyncio.sleep(2)  # 等选择页 SPA 就绪
                    await _kiro_click_signin_option(page, "Your organization")
                except Exception as e:
                    logger.debug(f"kiro 资源缓存：预热点 'Your organization' 跳过（忽略）: {e}")
                # 给懒加载 chunk + 可能的错误页自愈留时间：轮询 cache2 到够大或超时
                src = _base_cache_dir()
                deadline = time.time() + 45
                while time.time() < deadline:
                    await asyncio.sleep(3)
                    # 命中错误页就点一次 Retry 逼它重抓 chunk（点不到就算了）
                    try:
                        if await page.locator('text=/Kiro failed to load/i').count() > 0:
                            try:
                                await page.get_by_text(re.compile("Retry", re.I)).first.click(timeout=2000)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    if _dir_size(src) >= _ASSET_CACHE_MIN_BYTES:
                        break
            finally:
                await close_camoufox_persistent_context(cm)

            size = _dir_size(_base_cache_dir())
            if size >= _ASSET_CACHE_MIN_BYTES:
                logger.info(
                    f"kiro 资源缓存：基准预热完成（cache2 {size // 1024} KB），"
                    f"后续账号将直接播种、免冷加载")
            else:
                logger.warning(
                    f"kiro 资源缓存：预热后 cache2 仅 {size // 1024} KB"
                    f"（assets.app.kiro.dev 可能被代理/防火墙拦），本批降级为冷加载")
    except Exception as e:
        logger.warning(f"kiro 资源缓存：预热失败（忽略，降级冷加载）: {e}")


# CloakBrowser stealth 默认会注入 --no-sandbox，Chrome 顶部会弹"不受支持的命令行标记"
# 提示条。--test-type 是 Chromium 官方让自动化场景隐藏该提示条的 flag，必须搭配传。
_CLOAK_EXTRA_ARGS = [
    "--test-type",
    "--no-default-browser-check",
    "--no-first-run",
    "--disable-infobars",
]


# 屏幕可用区/窗口装饰尺寸在一次进程内不会变：探测一次后进程内复用，
# 并落盘到文件，让下次进程启动时 --window-size 直接用准确值（窗口不再先大后缩）。
_WINDOW_METRICS_FILE = os.path.expanduser("~/.cache/easay-login/window_metrics.json")
_window_metrics = None  # Optional[dict]


def _load_window_metrics_file():
    try:
        with open(_WINDOW_METRICS_FILE) as f:
            m = json.load(f)
        if all(isinstance(m.get(k), int) and m[k] > 0
               for k in ("work_w", "work_h", "vw", "vh")):
            return m
    except Exception:
        pass
    return None


def _save_window_metrics_file(m: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_WINDOW_METRICS_FILE), exist_ok=True)
        with open(_WINDOW_METRICS_FILE, "w") as f:
            json.dump(m, f)
    except Exception:
        pass


@functools.lru_cache(maxsize=1)
def _screen_size() -> tuple[int, int]:
    """探测当前显示器的逻辑分辨率（用于给浏览器窗口显式定尺寸）。
    macOS 上优先取 system_profiler 的 "UI Looks like"（缩放后逻辑分辨率），
    回退到原生 "Resolution"，再回退到 1920x1080。
    """
    default = (1920, 1080)
    try:
        out = subprocess.run(
            ["system_profiler", "SPDisplaysDataType"],
            capture_output=True, text=True, timeout=8,
        ).stdout
        # 优先逻辑分辨率
        m = re.search(r"UI Looks like:\s*(\d+)\s*x\s*(\d+)", out)
        if not m:
            m = re.search(r"Resolution:\s*(\d+)\s*x\s*(\d+)", out)
        if m:
            return int(m.group(1)), int(m.group(2))
    except Exception:
        pass
    return default


def best_known_viewport() -> dict:
    """给 persistent context 用的「显式」viewport 尺寸。

    persistent context 千万别用 no_viewport（viewport=None）：那样 fill/click 触发的
    scrollIntoViewIfNeeded 会报 "Viewport size not available"（见 new_window_sized_context
    注释，IDC 登录填用户名时就栽在这）。但也不能用 cloakbrowser 默认的固定 1920x947——
    比屏幕宽时整页会被等比缩小。折中：用 new_window_sized_context 实测并落盘的真实内容区
    尺寸（vw/vh），回退到屏幕逻辑分辨率。既不缩放、又保证 viewport 可读。
    """
    m = _window_metrics or _load_window_metrics_file()
    if m:
        return {"width": m["vw"], "height": m["vh"]}
    sw, sh = _screen_size()
    return {"width": sw, "height": sh}


async def launch_cloak_browser(maximized: bool = False):
    """用 CloakBrowser 启动 stealth Chromium，返回标准 playwright Browser。
    替代旧的 connect_over_cdp 到系统原生 Chrome 的方案：CloakBrowser 自带源码级
    指纹补丁的 Chromium，无需再借用本机 Chrome。

    maximized=True 时追加 --start-maximized，让窗口铺满当前屏幕（需配合
    new_context(no_viewport=True) 才能让页面视口随窗口大小自适应）。
    """
    args = list(_CLOAK_EXTRA_ARGS)
    if maximized:
        # macOS 上 --start-maximized 不可靠：窗口可能没真正最大化/被最小化/开在非当前
        # Space，导致 no_viewport=True 时 Playwright 读不到视口而报 "Viewport size not
        # available"。改用显式 --window-size + --window-position，窗口尺寸恒定可读。
        # 优先用上次实测的屏幕可用区（system_profiler 的全屏分辨率比可用区大，
        # 会导致窗口先超出屏幕再被 CDP 缩回，视觉上闪一下）。
        cached = _window_metrics or _load_window_metrics_file()
        if cached:
            sw, sh = cached["work_w"], cached["work_h"]
        else:
            sw, sh = _screen_size()
        args.append(f"--window-size={sw},{sh}")
        args.append("--window-position=0,0")
    browser = await launch_async(
        headless=HEADLESS,
        proxy=await _proxy_settings_async(),
        humanize=True,
        args=args,
    )
    logger.info(f"已启动 CloakBrowser stealth Chromium (backend={_PLAYWRIGHT_BACKEND})")
    return browser


async def _cdp_fit_window(context: BrowserContext, page: Page,
                          work_w: int, work_h: int) -> None:
    """用 CDP Browser.setWindowBounds 把物理窗口缩到屏幕可用区内（左上角对齐）。

    仅靠 new_context(viewport=...) 不够：viewport 只改页面渲染尺寸，物理 OS 窗口
    仍是启动 --window-size 指定的大小。若那个尺寸大于屏幕（system_profiler 的
    "UI Looks like" 缩放分辨率常常如此），窗口会溢出屏幕右/下边，底部控件点不到。
    setWindowBounds 直接把真实窗口拉回可用区，与 viewport 配合才能严丝合缝。
    """
    sess = await context.new_cdp_session(page)
    info = await sess.send("Browser.getWindowForTarget")
    await sess.send("Browser.setWindowBounds", {
        "windowId": info["windowId"],
        "bounds": {"left": 0, "top": 0, "width": work_w, "height": work_h},
    })


async def fit_window_to_screen(context: BrowserContext, page: Page) -> None:
    """把一个已存在的窗口铺满屏幕可用区（persistent context 专用）。

    前提：context 必须以 viewport=None（即 no_viewport）创建。cloakbrowser 的
    launch_persistent_context_async 默认注入固定 1920x947 viewport 仿真，仿真开着时
    这里读到的 screen.avail* 是仿真值（Playwright 里 screen 缺省等于 viewport）、
    页面也不随窗口重排，整个函数失效且小屏上整页被缩小。
    关掉仿真后页面按窗口自适应渲染，读真实 CSS 可用区再用 CDP 设窗口边界即可铺满。
    失败不影响主流程（顶多窗口还是默认小尺寸）。
    """
    try:
        m = await page.evaluate(
            "({aw:screen.availWidth, ah:screen.availHeight})")
        work_w, work_h = int(m["aw"]), int(m["ah"])
        await _cdp_fit_window(context, page, work_w, work_h)
        logger.info(f"窗口已铺满屏幕可用区 {work_w}x{work_h}")
    except Exception as e:
        logger.warning(f"铺满窗口失败（保持默认尺寸）: {e}")


async def _probe_window_metrics(browser):
    """开一个临时空白 context 读浏览器眼里真实的 CSS 可用区
    （screen.availWidth/Height）和窗口装饰尺寸（outer-inner），失败返回 None。
    """
    probe = None
    try:
        probe = await browser.new_context(no_viewport=True)
        ppage = await probe.new_page()
        m = await ppage.evaluate(
            "({aw:screen.availWidth, ah:screen.availHeight,"
            " cw:outerWidth-innerWidth, ch:outerHeight-innerHeight})")
        work_w, work_h = int(m["aw"]), int(m["ah"])
        return {"work_w": work_w, "work_h": work_h,
                "vw": work_w - int(m["cw"]), "vh": work_h - int(m["ch"])}
    except Exception as e:
        logger.warning(f"探测屏幕可用区失败: {e}")
        return None
    finally:
        if probe is not None:
            try:
                await probe.close()
            except Exception:
                pass


async def new_window_sized_context(browser, storage_state=None) -> BrowserContext:
    """新建一个「物理窗口铺满屏幕可用区、viewport 等于窗口内容区」的 context。

    storage_state：传一个 storage_state JSON 路径时，用它初始化 context（复用已保存的
    cookie/localStorage 登录会话，跳过重新登录）。文件不存在或加载失败则退回全新会话。

    分两条路径，按 browser.browser_type.name 自动分发：
      - **Firefox**（Camoufox / cloak_browser_session 现在的统一路径）：
        无 CDP，窗口尺寸在 AsyncCamoufox(window=(w,h)) 启动时已定死，这里委托给
        new_camoufox_context 走 viewport-only 路径。storage_state 跨内核不兼容时
        new_camoufox_context 自带兜底，会回退到全新会话。
      - **Chromium**（launch_real_chrome_incognito 真 Chrome over AWS WAF 那条平行路径）：
        保留 CDP Browser.setWindowBounds 那一整套逻辑 —— 真 Chrome 没有 Firefox 的
        window 启动参数等价物，必须运行时 CDP 把物理窗口缩到可用区。

    尺寸全程不依赖 system_profiler 的缩放分辨率（那是 CSS 像素的 1.x 倍，
    拿去设窗口会溢出屏幕），而是用临时空白窗实测一次：CSS 可用区
    （screen.availWidth/Height）减去窗口装饰（outer-inner）即正确 viewport。
    实测结果进程内缓存（批量跑多账号只闪一次探测窗）并落盘，下次进程启动时
    --window-size 直接用准确值，窗口不再先超屏再被 CDP 缩回。
    """
    # Firefox 路径：cloak_browser_session 现在统一走 Camoufox，无 CDP
    if browser.browser_type.name == "firefox":
        return await new_camoufox_context(browser, storage_state=storage_state)

    # 以下为 Chromium 路径（仅 launch_real_chrome_incognito 真 Chrome 使用）
    global _window_metrics
    if _window_metrics is None:
        metrics = await _probe_window_metrics(browser)
        if metrics:
            _window_metrics = metrics
            _save_window_metrics_file(metrics)
        else:
            # 兜底值也缓存，避免探测持续失败时每个账号都再闪一次探测窗
            sw, sh = _screen_size()
            _window_metrics = _load_window_metrics_file() or {
                "work_w": sw, "work_h": sh, "vw": sw, "vh": sh}
            logger.warning(
                f"使用兜底窗口尺寸 {_window_metrics['work_w']}x{_window_metrics['work_h']}")

    work_w, work_h = _window_metrics["work_w"], _window_metrics["work_h"]
    vw, vh = _window_metrics["vw"], _window_metrics["vh"]
    logger.info(f"窗口可用区: {work_w}x{work_h}，viewport: {vw}x{vh}")
    ctx_kwargs = {
        "viewport": {"width": vw, "height": vh},
        "screen": {"width": work_w, "height": work_h},
    }
    if storage_state and os.path.exists(storage_state):
        ctx_kwargs["storage_state"] = storage_state
        logger.info(f"复用已保存的登录会话: {storage_state}")
    try:
        context = await browser.new_context(**ctx_kwargs)
    except Exception as e:
        # storage_state 损坏/不兼容等 → 退回全新会话，绝不因复用失败而中断
        logger.warning(f"加载已保存会话失败，改用全新会话: {e}")
        ctx_kwargs.pop("storage_state", None)
        context = await browser.new_context(**ctx_kwargs)

    # 不在这里建页（会给业务流程留个多余空白 tab）。改成挂一次性钩子：等下游
    # context.new_page() 真正开页时，再用 CDP 把那个窗口缩到可用区。
    fitted = {"done": False}

    async def _fit(page: Page):
        if fitted["done"]:
            return
        fitted["done"] = True
        try:
            await _cdp_fit_window(context, page, work_w, work_h)
        except Exception as e:
            logger.warning(f"CDP 调整窗口尺寸失败（窗口可能溢出屏幕）: {e}")

    context.on("page", lambda page: asyncio.create_task(_fit(page)))
    return context


_CHROME_APP_BIN = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


async def connect_main_chrome_incognito(port: int = 9222):
    """连到「主 Chrome」开一个无痕上下文做自动化，返回
    (playwright, browser, context, proc, attached)。

    为什么不用 playwright.chromium.launch：那会给 Chrome 注入 --enable-automation 等
    自动化标志、navigator.webdriver=true，AWS WAF 一眼认出 → 触发 "Security check"。
    本函数走 CDP attach：Chrome 由「人/subprocess」干净启动（无自动化标志），再
    connect_over_cdp 连上去，指纹和你手动开的无痕窗口一致 → WAF 一般直接放行。

    顺序：
      1) 先试连 127.0.0.1:port —— 连上＝用你正在跑的主 Chrome（需它带
         --remote-debugging-port=port 启动）。此时 attached=True，清理时绝不关你的 Chrome。
      2) 连不上 → subprocess 干净启动真实 Chrome.app（独立临时 profile + 调试端口，
         不带任何自动化标志），再连。attached=False，清理时关掉这个实例。
    两种都用 browser.new_context() 开「无痕」上下文（CDP 下 new_context = 独立隐身会话）。

    清理（调用方负责）：
      - attached=True ：await context.close()（只关无痕窗）→ await pw.stop()，不要 browser.close()
      - attached=False：await context.close() → await browser.close() → proc.terminate() → pw.stop()
    """
    from playwright.async_api import async_playwright
    pw = await async_playwright().start()
    cdp = f"http://127.0.0.1:{port}"

    browser = None
    try:
        browser = await pw.chromium.connect_over_cdp(cdp)
        logger.info(f"已连上主 Chrome 调试端口 {port}（用你正在跑的 Chrome 开无痕窗）")
        attached = True
    except Exception:
        attached = False

    proc = None
    if browser is None:
        if not os.path.exists(_CHROME_APP_BIN):
            await pw.stop()
            raise RuntimeError(f"未找到系统 Chrome: {_CHROME_APP_BIN}")
        prof = tempfile.mkdtemp(prefix="kiro_chrome_")
        args = [
            _CHROME_APP_BIN,
            f"--remote-debugging-port={port}",
            f"--user-data-dir={prof}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ]
        logger.info("主 Chrome 调试端口未开，改用 subprocess 干净启动真实 Chrome.app（无自动化标志）")
        proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(40):
            try:
                browser = await pw.chromium.connect_over_cdp(cdp)
                break
            except Exception:
                await asyncio.sleep(0.5)
        if browser is None:
            try:
                proc.terminate()
            except Exception:
                pass
            await pw.stop()
            raise RuntimeError("启动真实 Chrome 后仍连不上 CDP 调试端口")
        logger.info("已干净启动真实 Chrome.app + CDP 连接")

    # CDP 下 new_context() = 全新隐身（无痕）上下文；首页自动铺满屏幕
    context = await new_window_sized_context(browser)
    return pw, browser, context, proc, attached


async def launch_real_chrome_incognito():
    """启动系统安装的真实 Chrome（channel="chrome"）做自动化，返回
    (playwright, browser, context)。用于需要真实 Chrome 指纹的场景——典型是过 AWS WAF
    "Security check" 人机校验：CloakBrowser 的魔改 Chromium 会被 WAF 拦，真 Chrome 一般
    直接放行。

    launch()（非持久化）本就用临时 user-data-dir、出块即弃，等价"无痕"（干净隔离会话、
    无任何已存 cookie/历史），且是真 Chrome 指纹——这正是过 WAF 的关键。不额外加
    --incognito 旗标（会和 new_context 叠出一个多余空白窗）。context 走
    new_window_sized_context 自动铺满屏幕。三个返回对象都需在用完后关闭
    （context.close / browser.close / playwright.stop）。
    """
    from playwright.async_api import async_playwright
    cached = _window_metrics or _load_window_metrics_file()
    if cached:
        sw, sh = cached["work_w"], cached["work_h"]
    else:
        sw, sh = _screen_size()
    args = [
        f"--window-size={sw},{sh}",
        "--window-position=0,0",
        "--no-first-run",
        "--no-default-browser-check",
    ]
    pw = await async_playwright().start()
    launch_kwargs = {"channel": "chrome", "headless": HEADLESS, "args": args}
    if PROXY:
        launch_kwargs["proxy"] = await _proxy_settings_async()
    browser = await pw.chromium.launch(**launch_kwargs)
    context = await new_window_sized_context(browser)
    logger.info("已启动真实系统 Chrome 无痕自动化上下文 (channel=chrome)")
    return pw, browser, context


@asynccontextmanager
async def cloak_browser_session(maximized: bool = False):
    """`async with cloak_browser_session() as browser:` 用法的便利封装。

    历史名义保留 —— 内部已统一切到 Camoufox stealth Firefox。8 个调用方
    （aws/aws-claude/aws-kiro/openai/single/claude/google/remote）代码零改动。

    切换原因：
      - Camoufox 是 patched Firefox，TLS/JA3 指纹是真实 Firefox 的，源码级抹掉
        navigator.webdriver / CDP 痕迹；CloakBrowser 是 patched Chromium，
        新版 Google "This browser may not be secure" / Codex / 部分站点的检测
        规则对 Chrome 系自动化更严，Firefox 路径过率显著高
      - geoip=True 自动按出口 IP 同步 timezone/locale/WebRTC，避免指纹矛盾

    例外不动 —— launch_real_chrome_incognito 那条真 Chrome 路径仍保留 CDP +
    Chromium，专门用于 AWS WAF Security check 这类反过来更看好真 Chrome 指纹的场景。

    注意：CloakBrowser/Chromium 旧 storage_state 与 Firefox 不兼容。new_camoufox_context
    内置兜底：加载失败自动回退全新会话，仅首次跑需重新登录、第二次起步即复用。
    """
    async with camoufox_browser_session(maximized=maximized) as browser:
        yield browser


# ============================================================
# Camoufox (Firefox-based) 路径：用于 CloakBrowser 被 WAF 拦的场景
# （目前仅 aws-kiro 使用）。Firefox 内核 + 源码级反指纹补丁，绕过
# Chrome 系自动化检测规则；缺点是无 CDP，所以 _cdp_fit_window 那套
# 物理窗口调整逻辑不可用 —— 改在 launch 时用 window=(w,h) 定死。
# ============================================================


def _camoufox_headless_value(force: bool = None):
    """决定 AsyncCamoufox 的 headless 参数值。

    force：按次覆盖 config 的 HEADLESS。None=用 config；True/False=强制开/关无头
    （命令行 --headless / --no-headless 走这里）。

      - 无头关：headless=False（GUI 可见）—— macOS dev 调试用
      - 无头开 + Linux：headless="virtual" —— 内置 Xvfb 虚拟显示，
        服务器无 X11 时仍能跑 humanize/canvas/WebGL（真 headless 会被检测）
      - 无头开 + macOS/Windows：headless=True —— Camoufox 的 "virtual"
        仅支持 Linux（"Virtual display is only supported on Linux."），其它平台
        退化到普通无头模式
    """
    on = HEADLESS if force is None else force
    if not on:
        return False
    if platform.system() == "Linux":
        return "virtual"
    return True


def _camoufox_window_size() -> tuple[int, int]:
    """Camoufox 启动窗口大小：复用 CloakBrowser 路径探测过/落盘过的
    work_w/work_h（屏幕可用区），否则退回 _screen_size。Firefox 无 CDP，
    必须在 launch 时定死，无法运行时改。"""
    cached = _window_metrics or _load_window_metrics_file()
    if cached:
        return cached["work_w"], cached["work_h"]
    return _screen_size()


@asynccontextmanager
async def camoufox_browser_session(maximized: bool = False, *,
                                   locale: str = None, timezone: str = None,
                                   os_name: str = None, geoip: bool = None):
    """Camoufox stealth Firefox 会话；与 cloak_browser_session API 对齐。

    用法：
        async with camoufox_browser_session(maximized=True) as browser:
            context = await new_camoufox_context(browser, storage_state=...)
            ...

    locale/timezone/os_name/geoip：可选覆盖，不传则取 config 的
    BROWSER_LOCALE / BROWSER_TIMEZONE / BROWSER_OS / BROWSER_GEOIP。

    与 CloakBrowser 路径的关键差异：
      - 内核：Firefox（vs Chromium），TLS/JA3 指纹也是 Firefox 的
      - CDP：无 —— context.new_cdp_session 在这里会抛错
      - 反指纹：编译期 patch（canvas/WebGL/screen/navigator.webdriver 等全在 C++ 层）
      - geoip=True 自动按出口 IP 同步 timezone/language/WebRTC，避免指纹矛盾
      - HEADLESS=True 时用 "virtual" 内置虚拟显示，Linux 服务器无需 xvfb

    maximized 当前仅影响日志/语义对齐（实际窗口大小始终按屏幕可用区算，
    Firefox 没有可靠的 OS 级 maximize 注入手段；保留参数是为了不破坏调用方）。
    """
    from camoufox.async_api import AsyncCamoufox
    w, h = _camoufox_window_size()
    proxy_cfg = await _proxy_settings_async()
    headless_val = _camoufox_headless_value()
    eff_locale = locale or BROWSER_LOCALE or "en-US"
    eff_os = os_name or BROWSER_OS or "windows"
    eff_geoip = await _resolve_geoip_async(geoip if geoip is not None else BROWSER_GEOIP)
    eff_tz = timezone or BROWSER_TIMEZONE
    logger.info(
        f"启动 Camoufox stealth Firefox "
        f"(headless={headless_val}, window={w}x{h}, "
        f"proxy={'yes' if proxy_cfg else 'no'}, maximized={maximized}, "
        f"locale={eff_locale}, tz={eff_tz or 'auto'}, os={eff_os}, geoip={eff_geoip})"
    )
    camoufox_kwargs = dict(
        headless=headless_val,
        humanize=True,
        geoip=eff_geoip,
        os=eff_os,
        locale=eff_locale,
        window=(w, h),
        proxy=proxy_cfg,
    )
    if eff_tz:
        camoufox_kwargs["env"] = {"TZ": eff_tz}
    async with AsyncCamoufox(**camoufox_kwargs) as browser:
        yield browser


async def new_camoufox_context(browser, storage_state=None) -> BrowserContext:
    """Camoufox/Firefox 版的 new_window_sized_context。

    关键差异：
      - 不调 _cdp_fit_window —— Firefox 无 CDP，窗口尺寸由 camoufox_browser_session
        在 launch 时通过 window=(w,h) 定死
      - viewport 显式设为窗口大小，避免 scrollIntoViewIfNeeded 报 "Viewport size not available"
      - storage_state 复用逻辑保持一致：按 admin 邮箱跨次复用登录态
    """
    w, h = _camoufox_window_size()
    ctx_kwargs = {"viewport": {"width": w, "height": h}}
    if storage_state and os.path.exists(storage_state):
        ctx_kwargs["storage_state"] = storage_state
        logger.info(f"复用已保存的登录会话: {storage_state}")
    try:
        return await browser.new_context(**ctx_kwargs)
    except Exception as e:
        logger.warning(f"加载已保存会话失败，改用全新会话: {e}")
        ctx_kwargs.pop("storage_state", None)
        return await browser.new_context(**ctx_kwargs)


async def launch_camoufox_persistent_context(user_data_dir: str, *,
                                             locale: str = None,
                                             timezone: str = None,
                                             os_name: str = None,
                                             geoip: bool = None,
                                             headless: bool = None,
                                             proxy: str = None):
    """启动 Camoufox 持久化 context（替代 cloakbrowser.launch_persistent_context_async）。
    返回 (context, _cm_handle)。调用方 finally 里调 close_camoufox_persistent_context(_cm_handle)
    完整清理（关 context + Firefox 进程 + Playwright + 虚拟显示）。

    locale/timezone/os_name/geoip：可选覆盖，不传则取 config 的
    BROWSER_LOCALE / BROWSER_TIMEZONE / BROWSER_OS / BROWSER_GEOIP。
    proxy：本次使用的代理 URL（如代理池轮换选出的），不传则用 config 的 PROXY。

    保持「先 await 拿 context、再 try/finally」的旧调用模式不变，避免业务逻辑大段缩进。

    用于 kiro mode：CloakBrowser 的 Chromium 会被 Google "This browser may not be secure"
    拦截，Firefox 内核绕过 Chrome 系自动化检测规则。geoip 自动按出口 IP 同步
    timezone/language/WebRTC；persistent profile 让第二次起步直接进登录态、风控等级
    显著低于"全新浏览器"。
    """
    from camoufox.async_api import AsyncCamoufox
    _seed_kiro_asset_cache(user_data_dir)
    w, h = _camoufox_window_size()
    proxy_cfg = await _proxy_settings_async(proxy)
    headless_val = _camoufox_headless_value(headless)
    eff_locale = locale or BROWSER_LOCALE or "en-US"
    eff_os = os_name or BROWSER_OS or "windows"
    eff_geoip = await _resolve_geoip_async(geoip if geoip is not None else BROWSER_GEOIP, proxy)
    eff_tz = timezone or BROWSER_TIMEZONE
    logger.info(
        f"启动 Camoufox stealth Firefox 持久化 context "
        f"(profile={user_data_dir}, headless={headless_val}, window={w}x{h}, "
        f"proxy={'yes' if proxy_cfg else 'no'}, "
        f"locale={eff_locale}, tz={eff_tz or 'auto'}, os={eff_os}, geoip={eff_geoip})"
    )
    camoufox_kwargs = dict(
        persistent_context=True,
        user_data_dir=user_data_dir,
        headless=headless_val,
        humanize=True,
        geoip=eff_geoip,
        os=eff_os,
        locale=eff_locale,
        window=(w, h),
        proxy=proxy_cfg,
    )
    if eff_tz:
        camoufox_kwargs["env"] = {"TZ": eff_tz}
    cm = AsyncCamoufox(**camoufox_kwargs)
    context = await cm.__aenter__()
    return context, cm


async def close_camoufox_persistent_context(cm) -> None:
    """关闭 launch_camoufox_persistent_context 返回的 _cm_handle。
    内部已吞异常 —— 调用方无需再 try/except 包裹。"""
    if cm is None:
        return
    try:
        await cm.__aexit__(None, None, None)
    except Exception as e:
        logger.warning(f"关闭 Camoufox persistent context 失败（忽略）: {e}")


# ============================================================
# kiro 登录浏览器后端分发：camoufox(Firefox) ↔ cloak(Chromium) 可切
# ------------------------------------------------------------
# 默认 camoufox：Firefox 内核过 Google "This browser may not be secure" 更稳。
# 切 cloak：CloakBrowser stealth Chromium，想用 Chrome 指纹/复用 chrome profile 时用。
# 两内核 profile 不兼容，按后端自动分流到不同 root（firefox / chrome）。
# ============================================================

# session 句柄：backend 供调用方判断是否跑 Firefox 专属 cache2 晋升；
# handle 是待清理对象（camoufox=AsyncCamoufox cm / cloak=persistent context）。
_KiroBrowserSession = namedtuple("_KiroBrowserSession", "backend handle")


def kiro_browser_backend() -> str:
    """kiro 登录浏览器后端：'camoufox'(默认) / 'cloak' / 'webkit' / 'safari'。
    优先级：环境变量 KIRO_BROWSER_BACKEND > config 的 KIRO_BROWSER_BACKEND > 'camoufox'。
    环境变量便于不改 config 直接 A/B（KIRO_BROWSER_BACKEND=safari ./run.sh kiro ...）。
      - camoufox : stealth Firefox，过 Google "browser may not be secure" 稳
      - cloak    : CloakBrowser stealth Chromium
      - webkit   : Playwright WebKit（Safari 引擎，仍带自动化痕迹，实测仍被 AWS WAF 拦）
      - safari   : 真 Safari via safaridriver（路线2）—— 实测能过 AWS WAF Security
                   check（同 IP 手动 DuckDuckGo 也过）；仅 register_kiro_idc device
                   flow 支持，走 Selenium 单会话（批量需串行）
      - botbrowser: BotBrowser（patched Chromium，源码级指纹伪装）—— Playwright 原生，
                   可并发/跨平台/无头；需 BOTBROWSER_EXEC_PATH（+ 可选 .enc profile）"""
    raw = (os.getenv("KIRO_BROWSER_BACKEND") or KIRO_BROWSER_BACKEND or "camoufox").strip().lower()
    if raw in ("cloak", "cloakbrowser", "chromium"):
        return "cloak"
    if raw in ("chrome", "realchrome", "real-chrome", "system-chrome"):
        return "chrome"
    if raw in ("webkit", "playwright-webkit"):
        return "webkit"
    if raw in ("safari", "safaridriver", "real-safari", "duckduckgo", "ddg"):
        return "safari"
    if raw in ("botbrowser", "bot", "botswin"):
        return "botbrowser"
    return "camoufox"


async def _launch_cloak_persistent_context(user_data_dir: str):
    """CloakBrowser stealth Chromium 持久化 context，语义对齐 camoufox 版：
    headless/proxy/geoip/humanize 一致。窗口用 --window-size 定死 + viewport=None
    让页面视口随真实窗口自适应（cloak 默认会注入固定 viewport 仿真，IDC 登录填
    用户名那步会栽，见 new_window_sized_context 注释）。返回持久化 context，其
    .close() 已被 cloakbrowser patch 成会一并 pw.stop()。"""
    w, h = _camoufox_window_size()
    args = list(_CLOAK_EXTRA_ARGS) + [f"--window-size={w},{h}", "--window-position=0,0"]
    proxy_cfg = await _proxy_settings_async()
    logger.info(
        f"启动 CloakBrowser stealth Chromium 持久化 context "
        f"(profile={user_data_dir}, headless={HEADLESS}, window={w}x{h}, "
        f"proxy={'yes' if proxy_cfg else 'no'})"
    )
    return await launch_persistent_context_async(
        user_data_dir=user_data_dir,
        headless=HEADLESS,
        proxy=proxy_cfg,
        args=args,
        viewport=None,      # → no_viewport：页面视口跟随物理窗口
        locale=BROWSER_LOCALE or "en-US",
        geoip=BROWSER_GEOIP,
        humanize=True,
    )


async def _launch_webkit_persistent_context(user_data_dir: str):
    """Playwright WebKit（Safari 引擎）持久化 context，返回 (context, pw)。
    pw 由本函数 start，关闭时必须一并 pw.stop()（不像 cloak 会自动 stop）。

    动机：macOS 上 DuckDuckGo(WebKit 内核) 手动登录同 IP 能过 AWS WAF Security
    check，而 Firefox/Chromium 自动化会被拦 → 引擎差异。这里用 WebKit 引擎自动化
    复现该效果。注意：Playwright webkit ≠ 真 Safari（UA/部分 API 指纹有差、带自动化
    痕迹、无 geoip），可能过、也可能仍被拦，属实测项。WebKit 不吃 chromium 的
    --window-size flag，窗口大小用 viewport 指定。"""
    from playwright.async_api import async_playwright
    w, h = _camoufox_window_size()
    proxy_cfg = await _proxy_settings_async()
    logger.info(
        f"启动 Playwright WebKit(Safari 引擎) 持久化 context "
        f"(profile={user_data_dir}, headless={HEADLESS}, viewport={w}x{h}, "
        f"proxy={'yes' if proxy_cfg else 'no'})"
    )
    pw = await async_playwright().start()
    try:
        context = await pw.webkit.launch_persistent_context(
            user_data_dir=user_data_dir,
            headless=HEADLESS,
            proxy=proxy_cfg,
            viewport={"width": w, "height": h},
            locale="en-US",
        )
    except Exception:
        await pw.stop()
        raise
    return context, pw


async def _launch_botbrowser_persistent_context(user_data_dir: str):
    """BotBrowser（patched Chromium，源码级指纹伪装）持久化 context，返回 (context, pw)。
    用原生 playwright chromium + executable_path 指向 BotBrowser 内核；--bot-profile
    传 .enc 指纹包。pw 由本函数 start，关闭时一并 pw.stop()。

    需在 config 配 BOTBROWSER_EXEC_PATH（内核可执行文件）；BOTBROWSER_PROFILE_PATH
    （.enc 指纹 profile）可选——留空则退化成普通 Chromium（无指纹伪装，但仍可跑）。"""
    from playwright.async_api import async_playwright
    if not BOTBROWSER_EXEC_PATH or not os.path.exists(BOTBROWSER_EXEC_PATH):
        raise RuntimeError(
            f"BotBrowser 内核未配置或不存在：BOTBROWSER_EXEC_PATH={BOTBROWSER_EXEC_PATH!r}。"
            "从 https://github.com/botswin/BotBrowser/releases 下载解压后，在 config.py 里填"
            "可执行文件路径（macOS 形如 /Applications/Chromium.app/Contents/MacOS/Chromium）")
    w, h = _camoufox_window_size()
    args = list(_CLOAK_EXTRA_ARGS) + [f"--window-size={w},{h}", "--window-position=0,0"]
    if BOTBROWSER_PROFILE_PATH:
        if not os.path.exists(BOTBROWSER_PROFILE_PATH):
            raise RuntimeError(
                f"BotBrowser .enc 指纹 profile 不存在：BOTBROWSER_PROFILE_PATH={BOTBROWSER_PROFILE_PATH!r}")
        args.append(f"--bot-profile={BOTBROWSER_PROFILE_PATH}")
    else:
        logger.warning("BotBrowser 未配置 .enc 指纹 profile（BOTBROWSER_PROFILE_PATH 空）"
                       "→ 退化成普通 Chromium，无指纹伪装")
    proxy_cfg = await _proxy_settings_async()
    logger.info(
        f"启动 BotBrowser (exec={BOTBROWSER_EXEC_PATH}, "
        f"profile={'yes' if BOTBROWSER_PROFILE_PATH else 'no'}, "
        f"headless={HEADLESS}, window={w}x{h}, proxy={'yes' if proxy_cfg else 'no'})")
    pw = await async_playwright().start()
    try:
        context = await pw.chromium.launch_persistent_context(
            user_data_dir=user_data_dir,
            executable_path=BOTBROWSER_EXEC_PATH,
            headless=HEADLESS,
            proxy=proxy_cfg,
            args=args,
            no_viewport=True,   # 页面视口跟随物理窗口
        )
    except Exception:
        await pw.stop()
        raise
    return context, pw


async def _launch_realchrome_persistent_context(user_data_dir: str):
    """系统真 Chrome（channel="chrome"）持久化 context，返回 (context, pw)。
    AWS WAF "Security check" 认正版 Chrome 二进制指纹直接放行（CloakBrowser 的 patched
    Chromium 会被拦）。去掉 --enable-automation 自动化标记，尽量贴近真人 Chrome。
    Playwright 原生 → register_kiro/apikey 现有流程可直接复用（不像 safari 走 Selenium）。"""
    from playwright.async_api import async_playwright
    w, h = _camoufox_window_size()
    args = list(_CLOAK_EXTRA_ARGS) + [f"--window-size={w},{h}", "--window-position=0,0"]
    proxy_cfg = await _proxy_settings_async()
    logger.info(
        f"启动系统真 Chrome 持久化 context "
        f"(profile={user_data_dir}, headless={HEADLESS}, window={w}x{h}, "
        f"proxy={'yes' if proxy_cfg else 'no'})")
    pw = await async_playwright().start()
    try:
        context = await pw.chromium.launch_persistent_context(
            user_data_dir=user_data_dir,
            channel="chrome",                              # 系统安装的正版 Chrome
            headless=HEADLESS,
            proxy=proxy_cfg,
            args=args,
            ignore_default_args=["--enable-automation"],   # 去掉自动化横幅/标记
            no_viewport=True,
        )
    except Exception:
        await pw.stop()
        raise
    return context, pw


async def launch_kiro_persistent_context(profile_email: str):
    """按 kiro_browser_backend() 选后端，启动 kiro 登录用持久化 context。

    返回 (context, profile_dir, session)：
      - context    : playwright BrowserContext
      - profile_dir: 实际 profile 目录（camoufox→firefox root / cloak→chrome root，
                     两内核 profile 不兼容，按后端隔离）
      - session    : 交给 close_kiro_persistent_context() 清理；session.backend
                     供调用方判断是否跑 Firefox 专属的 cache2 晋升
    """
    backend = kiro_browser_backend()
    if backend in ("safari", "chrome"):
        # safari/chrome 走 Selenium/WebDriver（app.kiro.safari_idc），产不出 Playwright
        # context。register_kiro_idc / register_kiro_apikey 有专门的 Selenium 分支；其它
        # Playwright 路径（社媒登录 / 资源预热）落到这里时回退 camoufox。
        logger.info(f"{backend} 后端走 Selenium，仅 kiro/kiro-apikey 支持；"
                    "当前 Playwright 路径回退 camoufox")
        backend = "camoufox"
    if backend == "cloak":
        profile_dir = get_kiro_profile_dir(profile_email, browser="chrome")
        context = await _launch_cloak_persistent_context(profile_dir)
        return context, profile_dir, _KiroBrowserSession("cloak", context)
    if backend == "webkit":
        profile_dir = get_kiro_profile_dir(profile_email, browser="webkit")
        context, pw = await _launch_webkit_persistent_context(profile_dir)
        return context, profile_dir, _KiroBrowserSession("webkit", (context, pw))
    if backend == "botbrowser":
        profile_dir = get_kiro_profile_dir(profile_email, browser="botbrowser")
        context, pw = await _launch_botbrowser_persistent_context(profile_dir)
        return context, profile_dir, _KiroBrowserSession("botbrowser", (context, pw))
    profile_dir = get_kiro_profile_dir(profile_email, browser="firefox")
    context, cm = await launch_camoufox_persistent_context(profile_dir)
    return context, profile_dir, _KiroBrowserSession("camoufox", cm)


async def close_kiro_persistent_context(session) -> None:
    """关闭 launch_kiro_persistent_context 返回的 session（内部吞异常，调用方无需包裹）。"""
    if session is None:
        return
    if session.backend == "cloak":
        try:
            await session.handle.close()  # cloak 的 context.close() 已 patch 成会 pw.stop()
        except Exception as e:
            logger.warning(f"关闭 CloakBrowser persistent context 失败（忽略）: {e}")
        return
    if session.backend in ("webkit", "botbrowser", "chrome"):
        # 都是 (context, pw)：pw 由我们 start，必须手动 stop
        context, pw = session.handle
        try:
            await context.close()
        except Exception as e:
            logger.warning(f"关闭 {session.backend} persistent context 失败（忽略）: {e}")
        try:
            await pw.stop()
        except Exception as e:
            logger.warning(f"停止 {session.backend} playwright 失败（忽略）: {e}")
        return
    await close_camoufox_persistent_context(session.handle)


async def wait_for_cloudflare(page: Page, timeout_s: int = 60) -> bool:
    """等待 Cloudflare challenge 通过，支持 Turnstile 自动勾选"""
    logger.info("等待 Cloudflare challenge 通过...")

    for i in range(timeout_s // 3):
        await page.wait_for_timeout(3000)
        current_url = page.url

        # challenge 已通过
        if "challenge" not in current_url and "challenge_redirect" not in current_url:
            logger.info(f"Cloudflare challenge 已通过 ({(i+1)*3}s)")
            return True

        # 尝试点击 Turnstile checkbox（在 iframe 内）
        try:
            turnstile_frame = page.frame_locator('iframe[src*="challenges.cloudflare.com"], iframe[src*="turnstile"]')
            checkbox = turnstile_frame.locator('input[type="checkbox"], .cb-lb')
            if await checkbox.count() > 0:
                logger.info("发现 Turnstile checkbox，尝试点击...")
                await checkbox.first.click()
                await page.wait_for_timeout(3000)
        except Exception:
            pass

        # 处理 challenge_redirect — 等待重定向完成
        if "challenge_redirect" in current_url:
            logger.info(f"challenge_redirect 检测中... ({(i+1)*3}s) URL: {current_url}")
            # 页面可能自动重定向，继续等待
            continue

        logger.debug(f"等待 Cloudflare... ({(i+1)*3}s) URL: {current_url}")

    logger.warning(f"Cloudflare challenge 超时未通过 ({timeout_s}s)")
    return False


def generate_totp(secret: str, digits: int = 6, period: int = 30,
                  for_time=None) -> str:
    """本地按 RFC 6238 (TOTP) 用密钥算出当前验证码，零依赖、零网络。

    secret: base32 编码的 TOTP 密钥（与 Google Authenticator 扫码的种子一致）。
    完全在本机计算：更快、不依赖任何外部服务端、密钥不出本机。
    """
    import base64, hmac, hashlib, struct, time
    s = re.sub(r"\s+", "", secret).upper()
    s += "=" * (-len(s) % 8)  # base32 需补齐到 8 的倍数
    key = base64.b32decode(s)
    counter = int((for_time if for_time is not None else time.time()) // period)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


async def get_totp_code(page: Page = None, secret: str = "") -> str:
    """用 TOTP 密钥本地生成验证码（不再打开网页/第三方网站）。

    保留 page 形参仅为兼容旧调用，内部不使用。
    """
    if not secret:
        raise RuntimeError("缺少 TOTP 密钥，无法生成验证码")
    code = generate_totp(secret)
    logger.info(f"本地生成 TOTP 验证码: {code}")
    return code


