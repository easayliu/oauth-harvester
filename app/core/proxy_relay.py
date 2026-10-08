"""本地 SOCKS5 中转：绕过 Playwright/Firefox「不支持带认证 SOCKS5 代理」的限制。

背景
----
Playwright 启动的 Firefox（camoufox）和 Chromium 内核都**不支持带账号密码的 SOCKS5
代理**，launch 时直接抛 `Browser does not support socks5 proxy authentication`。
但它们支持**无认证**的 SOCKS5。

做法
----
在 127.0.0.1 起一个**无认证** SOCKS5 服务，浏览器连它；它把每个 CONNECT 转发到真正
的**带认证上游** SOCKS5，认证（RFC1929 用户名/密码）和远程 DNS 都在转发这一层做掉。
浏览器侧完全看不到认证，限制即被绕过；同时保持远程 DNS（等价 socks5h），不泄漏 DNS。

仅当上游是 socks 且带账号密码时才需要中转；否则 ensure_relay() 返回 None，调用方按
原样把上游 URL 交给浏览器即可。
"""

import asyncio
import logging
import struct
from urllib.parse import urlsplit, unquote

logger = logging.getLogger(__name__)

# 进程内按上游 URL 缓存：同一个上游只起一个中转，复用其本地端口（代理池轮换时多个上游并存）。
_relays: dict = {}  # upstream_url -> (server, local_url)


async def ensure_relay(upstream_url: str):
    """按需启动本地无认证 SOCKS5 中转，返回 "socks5://127.0.0.1:<port>"。

    - upstream 不是 socks 或没有账号密码：无需中转，返回 None（调用方用原 URL）。
    - 已为同一 upstream 起过：直接复用，返回上次的本地 URL。
    """
    if not upstream_url:
        return None
    parts = urlsplit(upstream_url)
    scheme = (parts.scheme or "").lower()
    if not scheme.startswith("socks"):
        return None  # http(s) 代理 Playwright 原生支持认证，不用中转
    if not (parts.username or parts.password):
        return None  # 无认证的 socks，浏览器本就支持，不用中转

    if upstream_url in _relays:
        return _relays[upstream_url][1]  # 复用

    up_host = parts.hostname
    up_port = parts.port
    up_user = unquote(parts.username) if parts.username else None
    up_pass = unquote(parts.password) if parts.password else None

    async def handle(reader, writer):
        try:
            await _handle_client(reader, writer, up_host, up_port, up_user, up_pass)
        except Exception as e:
            logger.debug("proxy_relay: 连接处理异常: %s", e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    local_url = f"socks5://127.0.0.1:{port}"
    _relays[upstream_url] = (server, local_url)
    logger.info("proxy_relay: 本地无认证 SOCKS5 中转已启动 %s → 上游 %s:%s（带认证，远程 DNS）",
                local_url, up_host, up_port)
    return local_url


async def _handle_client(reader, writer, up_host, up_port, up_user, up_pass):
    """处理一条浏览器→本地中转的 SOCKS5 连接，转发到带认证上游。"""
    # --- 1) 与浏览器做无认证 SOCKS5 握手 ---
    ver, nmethods = struct.unpack("!BB", await _read_exact(reader, 2))
    if ver != 0x05:
        return
    await _read_exact(reader, nmethods)  # 丢弃浏览器支持的认证方法列表
    writer.write(b"\x05\x00")            # 选"无认证"
    await writer.drain()

    # --- 2) 读浏览器的 CONNECT 请求 ---
    ver, cmd, _rsv, atyp = struct.unpack("!BBBB", await _read_exact(reader, 4))
    if ver != 0x05 or cmd != 0x01:       # 只支持 CONNECT
        writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # command not supported
        await writer.drain()
        return

    if atyp == 0x01:      # IPv4
        raw = await _read_exact(reader, 4)
        dst_addr = ".".join(str(b) for b in raw)
        dst_atyp, dst_bytes = 0x01, raw
    elif atyp == 0x03:    # 域名
        dlen = (await _read_exact(reader, 1))[0]
        raw = await _read_exact(reader, dlen)
        dst_addr = raw.decode("ascii", errors="replace")  # 仅用于日志；转发用原始字节
        dst_atyp, dst_bytes = 0x03, bytes([dlen]) + raw  # 原样转发域名→上游做远程 DNS
    elif atyp == 0x04:    # IPv6
        raw = await _read_exact(reader, 16)
        dst_addr = raw.hex()
        dst_atyp, dst_bytes = 0x04, raw
    else:
        writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")  # address type not supported
        await writer.drain()
        return
    dst_port = struct.unpack("!H", await _read_exact(reader, 2))[0]

    # --- 3) 连上游并完成带认证握手 + CONNECT ---
    try:
        up_reader, up_writer = await asyncio.open_connection(up_host, up_port)
        await _upstream_handshake(up_reader, up_writer, up_user, up_pass,
                                  dst_atyp, dst_bytes, dst_port)
    except Exception as e:
        logger.debug("proxy_relay: 上游连接 %s:%s 失败: %s", dst_addr, dst_port, e)
        writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # connection refused
        await writer.drain()
        return

    # --- 4) 回复浏览器成功，开始双向透传 ---
    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    await writer.drain()
    await asyncio.gather(
        _pipe(reader, up_writer),
        _pipe(up_reader, writer),
        return_exceptions=True,
    )


async def _upstream_handshake(up_reader, up_writer, user, password,
                              dst_atyp, dst_bytes, dst_port):
    """对上游 SOCKS5 做 用户名/密码认证 + CONNECT。失败抛异常。"""
    # 提供"无认证(0x00)"和"用户名/密码(0x02)"两种方法
    up_writer.write(b"\x05\x02\x00\x02")
    await up_writer.drain()
    ver, method = struct.unpack("!BB", await _read_exact(up_reader, 2))
    if ver != 0x05:
        raise ConnectionError("上游非 SOCKS5")
    if method == 0x02:    # 需要 RFC1929 用户名/密码认证
        u = (user or "").encode()
        p = (password or "").encode()
        up_writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        await up_writer.drain()
        _, status = struct.unpack("!BB", await _read_exact(up_reader, 2))
        if status != 0x00:
            raise ConnectionError("上游认证失败")
    elif method != 0x00:
        raise ConnectionError(f"上游要求不支持的认证方法 0x{method:02x}")

    # CONNECT：把目标地址（域名则由上游做远程 DNS）发给上游
    up_writer.write(b"\x05\x01\x00" + bytes([dst_atyp]) + dst_bytes + struct.pack("!H", dst_port))
    await up_writer.drain()
    header = await _read_exact(up_reader, 4)
    ver, rep, _rsv, atyp = struct.unpack("!BBBB", header)
    if rep != 0x00:
        raise ConnectionError(f"上游 CONNECT 被拒 rep=0x{rep:02x}")
    # 读掉 BND.ADDR + BND.PORT
    if atyp == 0x01:
        await _read_exact(up_reader, 4 + 2)
    elif atyp == 0x03:
        dlen = (await _read_exact(up_reader, 1))[0]
        await _read_exact(up_reader, dlen + 2)
    elif atyp == 0x04:
        await _read_exact(up_reader, 16 + 2)


async def _read_exact(reader, n: int) -> bytes:
    data = await reader.readexactly(n)
    return data


async def _pipe(reader, writer):
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
