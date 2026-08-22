#!/usr/bin/env python3
"""
专有隧道 — 为 DeepSeek 服务绕过 WAF
=====================================
无需 SSH，使用自定义 TCP 协议 + token 认证。

用法:
  本机(HK): python3 tunnel.py server --port 9999 --socks 2080 --token 你的密码
  四川机:   python3 tunnel.py client --host tunnel.ltzy.top --port 9999 --token 你的密码

工作流程:
  本机 SOCKS5:2080  →  TCP 隧道  →  四川机  →  互联网
  acugw 配置 proxy_url = "socks5://127.0.0.1:2080" 即可使用
"""

import asyncio
import argparse
import struct
import hashlib
import hmac
import os
import sys
import time
import logging
import socket
from asyncio import StreamReader, StreamWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("tunnel")


# ============================================================
# 协议常量
# ============================================================
MAGIC = b"\xac\xe5\x07\x13"
VERSION = 1

CMD_AUTH = 0x01
CMD_AUTH_OK = 0x02
CMD_AUTH_FAIL = 0x03
CMD_CONNECT = 0x10
CMD_CONNECT_OK = 0x11
CMD_CONNECT_FAIL = 0x12
CMD_DATA = 0x20
CMD_CLOSE = 0x30
CMD_PING = 0x40
CMD_PONG = 0x41

AUTH_TIMEOUT = 10
IDLE_TIMEOUT = 300
CONNECT_TIMEOUT = 15


# ============================================================
# 帧编解码
# ============================================================
def make_frame(cmd: int, stream_id: int, payload: bytes = b"") -> bytes:
    """MAGIC(4) + version(1) + cmd(1) + stream_id(4) + len(4) + payload"""
    return MAGIC + struct.pack("!BBII", VERSION, cmd, stream_id, len(payload)) + payload


async def read_exact(reader: StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


async def read_frame(reader: StreamReader) -> tuple[int, int, bytes]:
    """读取一帧 (cmd, stream_id, payload)"""
    try:
        magic = await read_exact(reader, 4)
        if magic != MAGIC:
            raise ValueError(f"bad magic: {magic.hex()}")
        version, cmd = struct.unpack("!BB", await read_exact(reader, 2))
        stream_id = struct.unpack("!I", await read_exact(reader, 4))[0]
        payload_len = struct.unpack("!I", await read_exact(reader, 4))[0]
        payload = await read_exact(reader, payload_len) if payload_len > 0 else b""
        return cmd, stream_id, payload
    except asyncio.IncompleteReadError:
        raise EOFError("connection closed")


def make_token_hash(token: str) -> bytes:
    return hmac.new(b"tunnel-auth-v1", token.encode(), hashlib.sha256).digest()


# ============================================================
# SOCKS5 (RFC 1928)
# ============================================================
SOCKS_VERSION = 5
SOCKS_CMD_CONNECT = 1
SOCKS_ATYP_IPV4 = 1
SOCKS_ATYP_DOMAIN = 3
SOCKS_ATYP_IPV6 = 4


async def socks5_handshake(reader: StreamReader) -> tuple[int, str, int]:
    """返回 (atyp, host, port) — 注意：方法协商已在 _handle_socks 中完成"""
    ver, cmd, rsv, atyp = struct.unpack("!BBBB", await read_exact(reader, 4))
    if ver != SOCKS_VERSION or cmd != SOCKS_CMD_CONNECT:
        raise ValueError(f"unsupported socks cmd: {cmd}")

    if atyp == SOCKS_ATYP_IPV4:
        host = socket.inet_ntop(socket.AF_INET, await read_exact(reader, 4))
    elif atyp == SOCKS_ATYP_DOMAIN:
        host = (await read_exact(reader, (await read_exact(reader, 1))[0])).decode()
    elif atyp == SOCKS_ATYP_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, await read_exact(reader, 16))
    else:
        raise ValueError(f"bad atyp: {atyp}")

    port = struct.unpack("!H", await read_exact(reader, 2))[0]
    return atyp, host, port


async def socks5_send_reply(writer: StreamWriter, success: bool) -> None:
    rep = 0x00 if success else 0x01
    writer.write(struct.pack("!BBBB", SOCKS_VERSION, rep, 0x00, SOCKS_ATYP_IPV4))
    writer.write(b"\x00\x00\x00\x00\x00\x00")
    await writer.drain()


async def socks5_send_method(writer: StreamWriter) -> None:
    writer.write(struct.pack("!BB", SOCKS_VERSION, 0x00))
    await writer.drain()


# ============================================================
# 隧道池 (服务端) — 支持多通道
# ============================================================
class Tunnel:
    """单个隧道连接"""
    def __init__(self, reader, writer, peer):
        self.reader = reader
        self.writer = writer
        self.peer = peer
        self.pending: dict[int, tuple[StreamWriter, asyncio.Event]] = {}
        self.streams: dict[int, StreamWriter] = {}
        self.lock = asyncio.Lock()
        self.alive = True

_tunnels: list[Tunnel] = []
_tunnels_lock = asyncio.Lock()
_tunnel_index = 0


# ============================================================
# 客户端模式 — 四川主机
# ============================================================
async def client_mode(host: str, port: int, token: str):
    log.info(f"连接隧道服务器 {host}:{port} ...")
    while True:
        try:
            await _client_run(host, port, token)
        except (OSError, EOFError, asyncio.TimeoutError) as e:
            log.warning(f"断开: {e}，3 秒后重连...")
        await asyncio.sleep(3)


async def _client_run(host: str, port: int, token: str):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
    )
    log.info("已连接，开始认证...")

    # 认证
    writer.write(make_frame(CMD_AUTH, 0, make_token_hash(token)))
    await writer.drain()
    cmd, _, payload = await asyncio.wait_for(read_frame(reader), AUTH_TIMEOUT)
    if cmd == CMD_AUTH_FAIL:
        log.error(f"认证失败: {payload.decode(errors='replace')}")
        writer.close()
        return
    if cmd != CMD_AUTH_OK:
        log.error(f"认证异常: cmd={cmd}")
        writer.close()
        return
    log.info("认证成功")

    # 主循环
    streams: dict[int, tuple[StreamReader, StreamWriter]] = {}
    last_ping = time.monotonic()

    async def relay_from_target(sid: int, tr: StreamReader):
        try:
            while True:
                data = await tr.read(65536)
                if not data:
                    writer.write(make_frame(CMD_CLOSE, sid))
                    await writer.drain()
                    break
                writer.write(make_frame(CMD_DATA, sid, data))
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass

    async def close_stream(sid: int):
        if sid in streams:
            _, tw = streams.pop(sid)
            try:
                tw.close()
            except OSError:
                pass

    while True:
        try:
            cmd, sid, payload = await asyncio.wait_for(read_frame(reader), 30)
        except asyncio.TimeoutError:
            if time.monotonic() - last_ping > 60:
                writer.write(make_frame(CMD_PING, 0))
                await writer.drain()
                last_ping = time.monotonic()
            continue

        last_ping = time.monotonic()

        if cmd == CMD_PING:
            writer.write(make_frame(CMD_PONG, 0))
            await writer.drain()

        elif cmd == CMD_CONNECT:
            host_port = payload.decode()
            target_host, target_port = host_port.rsplit(":", 1)
            log.info(f"代理: {target_host}:{target_port}")
            try:
                tr, tw = await asyncio.wait_for(
                    asyncio.open_connection(target_host, int(target_port)),
                    timeout=CONNECT_TIMEOUT,
                )
                streams[sid] = (tr, tw)
                writer.write(make_frame(CMD_CONNECT_OK, sid))
                await writer.drain()
                asyncio.create_task(relay_from_target(sid, tr))
            except Exception as e:
                log.warning(f"连接失败 {target_host}:{target_port}: {e}")
                writer.write(make_frame(CMD_CONNECT_FAIL, sid, str(e).encode()))
                await writer.drain()

        elif cmd == CMD_DATA:
            if sid in streams:
                try:
                    _, tw = streams[sid]
                    tw.write(payload)
                    await tw.drain()
                except OSError:
                    await close_stream(sid)

        elif cmd == CMD_CLOSE:
            await close_stream(sid)

        elif cmd == CMD_PONG:
            pass


# ============================================================
# 服务端模式 — 本机(HK)
# ============================================================
async def server_mode(socks_port: int, tunnel_port: int, token: str):
    log.info(f"隧道监听 0.0.0.0:{tunnel_port}，等待四川连接...")
    log.info(f"SOCKS5 监听 127.0.0.1:{socks_port}")

    tunnel_srv = await asyncio.start_server(
        lambda r, w: _handle_tunnel(r, w, token), "0.0.0.0", tunnel_port
    )
    socks_srv = await asyncio.start_server(_handle_socks, "127.0.0.1", socks_port)

    log.info("全部就绪")
    await asyncio.gather(tunnel_srv.serve_forever(), socks_srv.serve_forever())


async def _handle_tunnel(reader: StreamReader, writer: StreamWriter, token: str):
    peer = writer.get_extra_info("peername")
    log.info(f"隧道连接: {peer}")

    # 认证
    try:
        cmd, _, payload = await asyncio.wait_for(read_frame(reader), AUTH_TIMEOUT)
    except (asyncio.TimeoutError, EOFError):
        writer.close()
        return

    if cmd != CMD_AUTH or not hmac.compare_digest(payload, make_token_hash(token)):
        writer.write(make_frame(CMD_AUTH_FAIL, 0, b"bad token"))
        await writer.drain()
        writer.close()
        log.warning(f"认证失败: {peer}")
        return

    writer.write(make_frame(CMD_AUTH_OK, 0))
    await writer.drain()
    log.info(f"认证成功: {peer}")

    tun = Tunnel(reader, writer, peer)
    async with _tunnels_lock:
        _tunnels.append(tun)
    log.info(f"隧道池: {len(_tunnels)} 通道在线")

    last_ping = time.monotonic()

    try:
        while True:
            try:
                cmd, sid, payload = await asyncio.wait_for(read_frame(reader), 30)
            except asyncio.TimeoutError:
                if time.monotonic() - last_ping > 60:
                    writer.write(make_frame(CMD_PING, 0))
                    await writer.drain()
                    last_ping = time.monotonic()
                continue

            last_ping = time.monotonic()

            if cmd == CMD_CONNECT_OK:
                async with tun.lock:
                    if sid in tun.pending:
                        sw, ev = tun.pending.pop(sid)
                        await socks5_send_reply(sw, True)
                        tun.streams[sid] = sw
                        ev.set()

            elif cmd == CMD_CONNECT_FAIL:
                async with tun.lock:
                    if sid in tun.pending:
                        sw, ev = tun.pending.pop(sid)
                        await socks5_send_reply(sw, False)
                        ev.set()
                        try:
                            sw.close()
                        except OSError:
                            pass

            elif cmd == CMD_DATA:
                async with tun.lock:
                    sw = tun.streams.get(sid)
                if sw:
                    try:
                        sw.write(payload)
                        await sw.drain()
                    except OSError:
                        async with tun.lock:
                            tun.streams.pop(sid, None)
                        try:
                            sw.close()
                        except OSError:
                            pass

            elif cmd == CMD_CLOSE:
                async with tun.lock:
                    sw = tun.streams.pop(sid, None)
                if sw:
                    try:
                        sw.close()
                    except OSError:
                        pass

            elif cmd == CMD_PONG:
                pass

            elif cmd == CMD_PING:
                writer.write(make_frame(CMD_PONG, 0))
                await writer.drain()

    except (OSError, EOFError, asyncio.IncompleteReadError) as e:
        log.warning(f"隧道断开: {peer} {e}")
    finally:
        tun.alive = False
        async with _tunnels_lock:
            if tun in _tunnels:
                _tunnels.remove(tun)
        log.info(f"隧道池: {len(_tunnels)} 通道在线")
        # 清理该隧道所有待处理连接
        async with tun.lock:
            for sw, ev in tun.pending.values():
                ev.set()
                try:
                    sw.close()
                except OSError:
                    pass
            tun.pending.clear()
            for sw in tun.streams.values():
                try:
                    sw.close()
                except OSError:
                    pass
            tun.streams.clear()
        try:
            writer.close()
        except OSError:
            pass


async def _handle_socks(reader: StreamReader, writer: StreamWriter):
    global _tunnel_index
    try:
        # 方法协商
        ver, nmethods = struct.unpack("!BB", await asyncio.wait_for(read_exact(reader, 2), 10))
        if ver != SOCKS_VERSION:
            return
        await read_exact(reader, nmethods)
        await socks5_send_method(writer)

        # 请求
        atyp, host, port = await asyncio.wait_for(socks5_handshake(reader), 10)
        log.info(f"SOCKS5 → {host}:{port}")

        # 从隧道池选一个通道 (轮询，跳过数据中心 IP)
        async with _tunnels_lock:
            # 优先选家庭宽带 IP（陕西电信 36.x / 中国移动 120.x 等）
            live = [t for t in _tunnels if t.alive]
            # 过滤掉已知数据中心 IP
            dc_ips = {}  # 填入你的住宅IP
            home = [t for t in live if t.peer[0] not in dc_ips]
            if not home:
                home = live  # 回退到全部
            if not home:
                await socks5_send_reply(writer, False)
                log.warning("SOCKS5: 无可用隧道")
                return
            _tunnel_index = (_tunnel_index + 1) % len(home)
            tun = home[_tunnel_index]

        # 分配 stream_id
        import random
        sid = random.randint(1, 0x7FFFFFFF)
        async with tun.lock:
            while sid in tun.pending or sid in tun.streams:
                sid = random.randint(1, 0x7FFFFFFF)

        ev = asyncio.Event()
        async with tun.lock:
            tun.pending[sid] = (writer, ev)

        # 发送 CONNECT
        async with tun.lock:
            tun.writer.write(make_frame(CMD_CONNECT, sid, f"{host}:{port}".encode()))
            await tun.writer.drain()

        # 等待结果
        try:
            await asyncio.wait_for(ev.wait(), timeout=30)
        except asyncio.TimeoutError:
            async with tun.lock:
                tun.pending.pop(sid, None)
            return

        # 如果连接成功，双向转发数据
        async with tun.lock:
            ok = sid in tun.streams
        if not ok:
            return

        # 转发客户端 → 隧道的数据
        try:
            while True:
                data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
                if not data:
                    break
                async with tun.lock:
                    if tun.alive:
                        tun.writer.write(make_frame(CMD_DATA, sid, data))
                        await tun.writer.drain()
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            async with tun.lock:
                if tun.alive:
                    tun.writer.write(make_frame(CMD_CLOSE, sid))
                    try:
                        await tun.writer.drain()
                    except OSError:
                        pass

    except (ValueError, asyncio.TimeoutError, OSError) as e:
        log.debug(f"SOCKS5 错误: {e}")
    finally:
        try:
            writer.close()
        except OSError:
            pass


# ============================================================
# 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="专有隧道 — DeepSeek WAF 绕过")
    sub = parser.add_subparsers(dest="mode", required=True)

    sp = sub.add_parser("server", help="本机(HK)运行")
    sp.add_argument("--port", type=int, default=9999, help="隧道端口 (默认 9999)")
    sp.add_argument("--socks", type=int, default=2080, help="SOCKS5 端口 (默认 2080)")
    sp.add_argument("--token", type=str, required=True, help="认证密码")

    cp = sub.add_parser("client", help="四川主机运行")
    cp.add_argument("--host", type=str, default="tunnel.ltzy.top", help="服务器地址")
    cp.add_argument("--port", type=int, default=9999, help="隧道端口")
    cp.add_argument("--token", type=str, required=True, help="认证密码")

    args = parser.parse_args()

    if args.mode == "server":
        asyncio.run(server_mode(args.socks, args.port, args.token))
    elif args.mode == "client":
        asyncio.run(client_mode(args.host, args.port, args.token))


if __name__ == "__main__":
    main()