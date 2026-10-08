"""浏览器出口代理池：批量登录时每个账号轮换一个代理，避免所有账号都从同一个出口 IP 出去。

config.py 的 PROXY_POOL 可以是 URL 列表，也可以是文件路径（每行一个 URL，# 开头为注释）。
轮换从随机位置开始（重跑不会总从第一个代理开始），取到的代理先用 check_proxy 测一次
出口 IP，不通的标记为坏并跳过，本进程内不再使用。
"""

import asyncio
import importlib.util
import logging
import os
import random
from urllib.parse import urlsplit

from app.settings import PROXY_POOL

logger = logging.getLogger(__name__)

_pool = None  # 进程内单例，首次 next_proxy() 时按 PROXY_POOL 建


def mask_proxy(url: str) -> str:
    """日志用：隐藏代理 URL 里的密码。"""
    parts = urlsplit(url)
    if not parts.password:
        return url
    netloc = f"{parts.username}:***@{parts.hostname}" + (f":{parts.port}" if parts.port else "")
    return parts._replace(netloc=netloc).geturl()


def load_proxy_pool(source=None) -> list:
    """把 PROXY_POOL（列表或文件路径）解析成去重后的 URL 列表。"""
    source = PROXY_POOL if source is None else source
    if not source:
        return []
    if isinstance(source, str):
        if not os.path.isfile(source):
            raise RuntimeError(f"PROXY_POOL 文件不存在: {source}")
        with open(source, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    else:
        lines = list(source)
    urls = [u.strip() for u in lines if u and u.strip() and not u.strip().startswith("#")]
    return list(dict.fromkeys(urls))


class ProxyPool:
    def __init__(self, urls: list):
        self.urls = urls
        self._i = random.randrange(len(urls)) if urls else 0
        self.dead = set()

    def __len__(self):
        return len(self.urls)

    async def next(self) -> str:
        """轮换取下一个可用代理；全部不可用时抛 RuntimeError。"""
        from app.core.browser import check_proxy
        loop = asyncio.get_event_loop()
        for _ in range(len(self.urls)):
            url = self.urls[self._i % len(self.urls)]
            self._i += 1
            if url in self.dead:
                continue
            scheme = (urlsplit(url).scheme or "").lower()
            if scheme.startswith("socks") and importlib.util.find_spec("socks") is None:
                # 没装 PySocks 测不了 socks，不测直接用（不能因此把代理全标坏）
                logger.info(f"代理池：本账号用 {mask_proxy(url)}（未装 PySocks，跳过连通性检测）")
                return url
            ip = await loop.run_in_executor(None, lambda: check_proxy(proxy_url=url))
            if not ip:
                self.dead.add(url)
                logger.warning(f"代理池：{mask_proxy(url)} 不可用，标记跳过"
                               f"（剩余可用 {len(self.urls) - len(self.dead)}/{len(self.urls)}）")
                continue
            logger.info(f"代理池：本账号用 {mask_proxy(url)}（出口 IP {ip}）")
            return url
        raise RuntimeError(f"代理池里 {len(self.urls)} 个代理全部不可用")


def get_proxy_pool():
    """返回进程内代理池单例；PROXY_POOL 未配置时返回 None（调用方回退到 PROXY）。"""
    global _pool
    if _pool is None:
        urls = load_proxy_pool()
        if not urls:
            return None
        _pool = ProxyPool(urls)
        logger.info(f"代理池已加载 {len(urls)} 个代理，按账号轮换")
    return _pool
