"""
HTTP proxy conformance tests.
- Reverse proxy: hop-by-hop stripping (RFC 9110 §7.6.1), forwarding headers (RFC 7239).
- Forward proxy: CONNECT tunneling (RFC 9110 §9.3.6).
- Client-through-proxy: CONNECT for https, absolute-form for http (RFC 9112 §3.2).
"""
from __future__ import annotations

import socket
import asyncio

from kaede.api.models import Callback, Listener
from kaede.api import server, client
from kaede.http.models import Request, Response, Headers
from kaede.http.proxy import ReverseProxy, hop_by_hop_fields


def _server_socket() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(socket.SOMAXCONN)
    sock.setblocking(False)
    return sock, sock.getsockname()[1]


async def _serve_h1(callback, **cfg_kwargs):
    sock, port = _server_socket()
    cfg = server.Config(bind_http=[], bind_https=[], bind_quic=[], protocols=["http/1.1"], **cfg_kwargs)
    h = server.Handler(Listener(sock=sock, kind="http"), callback, cfg)
    await h.start()
    return h, port


# ---------------------------------------------------------------------------
# Hop-by-hop field computation (RFC 9110 §7.6.1)
# ---------------------------------------------------------------------------

class TestHopByHop:
    def test_fixed_set(self):
        fields = hop_by_hop_fields(Headers({}))
        assert "transfer-encoding" in fields
        assert "upgrade" in fields
        assert "proxy-authorization" in fields

    def test_connection_named_fields(self):
        fields = hop_by_hop_fields(Headers({"Connection": "X-Custom, close"}))
        assert "x-custom" in fields
        assert "close" in fields


# ---------------------------------------------------------------------------
# Reverse proxy
# ---------------------------------------------------------------------------

class OriginCallback(Callback):
    async def on_request(self, request):
        xff = request.headers.get("X-Forwarded-For") or ""
        proto = request.headers.get("X-Forwarded-Proto") or ""
        headers = Headers({"X-Origin": "yes", "Connection": "X-Secret", "X-Secret": "leak"})
        body = f"origin {request.target} xff={xff} proto={proto}".encode()
        return Response(body, content_type="text/plain", headers=headers)


class TestReverseProxy:
    async def test_forward_and_strip_hop_by_hop(self):
        origin, origin_port = await _serve_h1(OriginCallback())

        rp = ReverseProxy(f"http://127.0.0.1:{origin_port}")

        class ProxyCallback(Callback):
            async def on_request(self, request):
                return await rp.forward(request, streaming=False)

        proxy, proxy_port = await _serve_h1(ProxyCallback())

        try:
            ch = client.Handler(client.Config(protocols=["http/1.1"]))
            conn = await ch.get_connection("http", "127.0.0.1", proxy_port, f"127.0.0.1:{proxy_port}")
            resp = await conn.request(Request(method="GET", target="/hello", headers=Headers({}), scheme="http"), streaming=False)

            assert resp.status_code == 200
            assert b"origin /hello" in resp.body
            # the immediate client's address was added (RFC 7239 / X-Forwarded-For)
            assert b"xff=127.0.0.1" in resp.body
            assert b"proto=http" in resp.body
            # upstream hop-by-hop fields must not leak to the downstream client
            assert "x-secret" not in resp.headers
            # but ordinary upstream headers are relayed
            assert resp.headers.get("X-Origin") == "yes"
        finally:
            await rp.close()
            for h in (origin, proxy):
                await h.drain(timeout=2.0)
                await h.stop()


# ---------------------------------------------------------------------------
# Forward proxy: CONNECT tunnel
# ---------------------------------------------------------------------------

class TestForwardProxy:
    async def test_connect_tunnel_relays_bytes(self):
        loop = asyncio.get_running_loop()

        # raw TCP echo "origin"
        class Echo(asyncio.Protocol):
            def connection_made(self, transport):
                self.transport = transport
            def data_received(self, data):
                self.transport.write(data)

        echo_server = await loop.create_server(Echo, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]

        proxy, proxy_port = await _serve_h1(Callback(), forward_proxy=True)

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n".encode())
            await writer.drain()

            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
            assert b"200" in header.split(b"\r\n", 1)[0]

            writer.write(b"ping-through-tunnel")
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(len(b"ping-through-tunnel")), timeout=5.0)
            assert echoed == b"ping-through-tunnel"

            writer.close()
        finally:
            echo_server.close()
            await echo_server.wait_closed()
            await proxy.drain(timeout=2.0)
            await proxy.stop()

    async def test_connect_disabled_by_default(self):
        # without forward_proxy the server must not tunnel CONNECT
        proxy, proxy_port = await _serve_h1(Callback())
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            writer.write(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            await writer.drain()
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
            # default callback answers normally; it is not a 200 Connection Established tunnel
            assert b"Connection Established" not in header
            writer.close()
        finally:
            await proxy.drain(timeout=2.0)
            await proxy.stop()


# ---------------------------------------------------------------------------
# Client through a proxy
# ---------------------------------------------------------------------------

class TestClientViaProxy:
    async def test_https_via_connect(self, tls_cert):
        from kaede.tls.models import TLSServerConfig, TLSClientConfig

        certfile, keyfile = tls_cert

        # https origin (HTTP/1.1 over TLS)
        osock, origin_port = _server_socket()
        ocfg = server.Config(bind_http=[], bind_https=[], bind_quic=[], protocols=["http/1.1"], tls=TLSServerConfig(certfile=certfile, keyfile=keyfile))

        class OriginCb(Callback):
            async def on_request(self, request):
                return Response(b"secure-origin", content_type="text/plain")

        origin = server.Handler(Listener(sock=osock, kind="https"), OriginCb(), ocfg)
        await origin.start()

        # plaintext forward proxy
        proxy, proxy_port = await _serve_h1(Callback(), forward_proxy=True)

        try:
            ch = client.Handler(client.Config(
                protocols=["http/1.1"],
                tls=TLSClientConfig(verify=False, check_hostname=False),
                proxy=f"http://127.0.0.1:{proxy_port}",
            ))
            conn = await ch.get_connection("https", "127.0.0.1", origin_port, f"127.0.0.1:{origin_port}")
            resp = await conn.request(Request(method="GET", target="/", headers=Headers({}), scheme="https", secure=True), streaming=False)
            assert resp.status_code == 200
            assert resp.body == b"secure-origin"
        finally:
            await ch.close()
            await proxy.drain(timeout=2.0)
            await proxy.stop()
            await origin.drain(timeout=2.0)
            await origin.stop()

    async def test_http_uses_absolute_form(self):
        loop = asyncio.get_running_loop()
        captured: list[bytes] = []

        # stub proxy: capture the request line, return a canned response
        class StubProxy(asyncio.Protocol):
            def __init__(self):
                self.buf = bytearray()
            def connection_made(self, transport):
                self.transport = transport
            def data_received(self, data):
                self.buf.extend(data)
                if b"\r\n\r\n" in self.buf:
                    captured.append(bytes(self.buf.split(b"\r\n", 1)[0]))
                    self.transport.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
                    self.transport.close()

        stub = await loop.create_server(StubProxy, "127.0.0.1", 0)
        stub_port = stub.sockets[0].getsockname()[1]

        try:
            cl = client.Client(client.Config(protocols=["http/1.1"], proxy=f"http://127.0.0.1:{stub_port}"))
            resp = await cl.get("http://example.com/path?q=1")
            await cl.close()

            assert resp.status_code == 200
            assert resp.body == b"hi"
            # RFC 9112 §3.2.2: requests to a proxy use absolute-form
            assert captured
            assert captured[0] == b"GET http://example.com/path?q=1 HTTP/1.1"
        finally:
            stub.close()
            await stub.wait_closed()
