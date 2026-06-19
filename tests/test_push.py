"""
Server push conformance tests.
RFC 9113 §8.4 (HTTP/2 PUSH_PROMISE) and RFC 9114 §4.6 / §7.2.7 (HTTP/3 push).
Validated against the RFC specifications, not current Kaede behavior.
"""
from __future__ import annotations

import socket
import asyncio

from kaede.api.models import Callback, Listener
from kaede.api import server, client
from kaede.http.h2 import H2Connection
from kaede.http.h3 import H3Connection
from kaede.http.models import Request, Response, Headers, PushPromise


def _server_socket() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(socket.SOMAXCONN)
    sock.setblocking(False)
    return sock, sock.getsockname()[1]


class PushCallback(Callback):
    async def on_request(self, request):
        if request.target == "/style.css":
            return Response(b"body{margin:0}", content_type="text/css")
        if request.target == "/app.js":
            return Response(b"console.log(1)", content_type="application/javascript")
        resp = Response(b"<html>", content_type="text/html")
        resp.push_promises = [PushPromise("/style.css"), PushPromise("/app.js")]
        return resp


# ---------------------------------------------------------------------------
# Push-gating logic (no full connection required)
# ---------------------------------------------------------------------------

class TestGating:
    def test_h2_no_push_when_peer_disables(self):
        class _Remote:
            enable_push = False

        class _Conn:
            remote_settings = _Remote()

        conn = H2Connection.__new__(H2Connection)
        conn.connection = _Conn()
        req = Request(method="GET", target="/", headers=Headers({"Host": "x"}), scheme="https", secure=True)
        assert conn.reserve_push(1, req, PushPromise("/a")) is None

    def test_h3_no_push_without_max_push_id(self):
        conn = H3Connection.__new__(H3Connection)
        conn.peer_max_push_id = None
        conn.next_push_id = 0
        req = Request(method="GET", target="/", headers=Headers({"Host": "x"}), scheme="https", secure=True)
        assert conn.reserve_push(0, req, PushPromise("/a")) is None

    def test_h3_no_push_when_exhausted(self):
        conn = H3Connection.__new__(H3Connection)
        conn.peer_max_push_id = 0
        conn.next_push_id = 1  # already past the allowed maximum
        req = Request(method="GET", target="/", headers=Headers({"Host": "x"}), scheme="https", secure=True)
        assert conn.reserve_push(0, req, PushPromise("/a")) is None


# ---------------------------------------------------------------------------
# HTTP/2 server push end-to-end (real TLS loopback + kaede client)
# ---------------------------------------------------------------------------

class TestH2Push:
    async def _serve(self, callback, tls_cert):
        from kaede.tls.models import TLSServerConfig
        certfile, keyfile = tls_cert
        sock, port = _server_socket()
        cfg = server.Config(bind_http=[], bind_https=[], bind_quic=[], protocols=["h2"], tls=TLSServerConfig(certfile=certfile, keyfile=keyfile))
        h = server.Handler(Listener(sock=sock, kind="https"), callback, cfg)
        await h.start()
        return h, port

    async def _get(self, port):
        from kaede.tls.models import TLSClientConfig
        ch = client.Handler(client.Config(protocols=["h2"], tls=TLSClientConfig(verify=False, check_hostname=False)))
        conn = await ch.get_connection("https", "127.0.0.1", port, f"127.0.0.1:{port}")
        return await conn.request(Request(method="GET", target="/", headers=Headers({}), scheme="https", secure=True), streaming=False)

    async def test_pushes_delivered(self, tls_cert):
        h, port = await self._serve(PushCallback(), tls_cert)
        try:
            resp = await self._get(port)
            assert resp.status_code == 200
            assert resp.body == b"<html>"
            assert resp.pushes is not None
            paths = {p.pushed_path: p for p in resp.pushes}
            assert paths.keys() == {"/style.css", "/app.js"}
            assert paths["/style.css"].body == b"body{margin:0}"
            assert paths["/app.js"].body == b"console.log(1)"
        finally:
            await h.drain(timeout=2.0)
            await h.stop()

    async def test_no_push_without_promises(self, tls_cert):
        class Plain(Callback):
            async def on_request(self, request):
                return Response(b"x", content_type="text/plain")

        h, port = await self._serve(Plain(), tls_cert)
        try:
            resp = await self._get(port)
            assert resp.status_code == 200
            assert not resp.pushes
        finally:
            await h.drain(timeout=2.0)
            await h.stop()


# ---------------------------------------------------------------------------
# HTTP/3 server push end-to-end (loopback)
# ---------------------------------------------------------------------------

class TestH3Push:
    async def test_pushes_delivered(self, h3_loopback):
        lb = h3_loopback(PushCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.status_code == 200
        assert resp.body == b"<html>"
        assert resp.pushes is not None
        paths = {p.pushed_path: p for p in resp.pushes}
        assert paths.keys() == {"/style.css", "/app.js"}
        assert paths["/style.css"].body == b"body{margin:0}"
        assert paths["/style.css"].headers.get("content-type") == "text/css; charset=utf-8"
        assert paths["/app.js"].body == b"console.log(1)"

    async def test_no_push_without_promises(self, h3_loopback):
        class Plain(Callback):
            async def on_request(self, request):
                return Response(b"x", content_type="text/plain")

        lb = h3_loopback(Plain())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.status_code == 200
        assert not resp.pushes
