"""
103 Early Hints conformance tests (RFC 8297).

The server must be able to emit one (or more) 103 informational responses,
carrying Link header fields, *before* the final response.  Clients that do not
understand 103 ignore it, so the final response must be unaffected.
"""
from __future__ import annotations

import socket
import asyncio
import pytest

from kaede.api.models import Callback, Listener
from kaede.api import server, client
from kaede.http.models import Request, Response, Headers
from kaede.http.headers import LinkValue
from kaede.http.process import normalize_early_hints


def _server_socket() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(socket.SOMAXCONN)
    sock.setblocking(False)
    return sock, sock.getsockname()[1]


# ---------------------------------------------------------------------------
# normalize_early_hints: the shared, protocol-agnostic conversion
# ---------------------------------------------------------------------------

class TestNormalize:
    def test_none(self):
        assert normalize_early_hints(None) == []

    def test_empty_list(self):
        assert normalize_early_hints([]) == []

    def test_linkvalue_list_becomes_link_header(self):
        out = normalize_early_hints([LinkValue("/a.css", {"rel": "preload", "as": "style"})])
        assert out == [("Link", '</a.css>; rel=preload; as=style')]

    def test_multiple_linkvalues_single_header(self):
        out = normalize_early_hints([LinkValue("/a", {"rel": "preload"}), LinkValue("/b", {"rel": "preload"})])
        assert out == [("Link", "</a>; rel=preload, </b>; rel=preload")]

    def test_tuple_list(self):
        out = normalize_early_hints([("Link", "</a>; rel=preload")])
        assert out == [("Link", "</a>; rel=preload")]

    def test_headers_object(self):
        h = Headers({"Link": "</a>; rel=preload"})
        h.append("X-Hint", "1")
        out = normalize_early_hints(h)
        assert ("link", "</a>; rel=preload") in out
        assert ("x-hint", "1") in out


# ---------------------------------------------------------------------------
# HTTP/1.1 wire format and ordering (RFC 8297 §2): 103 precedes the final
# response and carries the Link field.  Verified with a raw socket so the
# interim response — which the kaede client transparently skips — is visible.
# ---------------------------------------------------------------------------

class HintCallback(Callback):
    async def on_request(self, request):
        return Response(b"final", content_type="text/plain")

    async def early_hints(self, request):
        return [LinkValue("/style.css", {"rel": "preload", "as": "style"})]


class TestHTTP1Wire:
    async def _serve(self, callback):
        sock, port = _server_socket()
        cfg = server.Config(bind_http=[], bind_https=[], bind_quic=[], protocols=["http/1.1"])
        h = server.Handler(Listener(sock=sock, kind="http"), callback, cfg)
        await h.start()
        return h, port

    async def test_103_precedes_200_with_link(self):
        h, port = await self._serve(HintCallback())
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            await writer.drain()

            data = await asyncio.wait_for(reader.read(-1), timeout=5.0)
            writer.close()
        finally:
            await h.drain(timeout=2.0)
            await h.stop()

        text = data.decode("latin-1")
        assert "103 Early Hints" in text
        assert "200" in text
        # 103 must come before the final 200 (RFC 8297 §2)
        assert text.index("103 Early Hints") < text.index("200")
        # the Link field must appear in the 103 block
        hint_block = text[: text.index("200")]
        assert "</style.css>; rel=preload; as=style" in hint_block
        assert data.endswith(b"final")

    async def test_no_hints_no_103(self):
        class Plain(Callback):
            async def on_request(self, request):
                return Response(b"x", content_type="text/plain")

        h, port = await self._serve(Plain())
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), timeout=5.0)
            writer.close()
        finally:
            await h.drain(timeout=2.0)
            await h.stop()

        assert b"103" not in data
        assert data.endswith(b"x")


# ---------------------------------------------------------------------------
# HTTP/2 and HTTP/3: emitting 103 on a real connection must not disturb the
# final response (the client ignores the interim per RFC 9113/9114).
# ---------------------------------------------------------------------------

class TestHTTP2Path:
    async def test_final_response_intact_with_hints(self, tls_cert):
        from kaede.tls.models import TLSServerConfig, TLSClientConfig

        certfile, keyfile = tls_cert
        sock, port = _server_socket()
        cfg = server.Config(bind_http=[], bind_https=[], bind_quic=[], protocols=["h2"], tls=TLSServerConfig(certfile=certfile, keyfile=keyfile))
        h = server.Handler(Listener(sock=sock, kind="https"), HintCallback(), cfg)
        await h.start()
        try:
            ch = client.Handler(client.Config(protocols=["h2"], tls=TLSClientConfig(verify=False, check_hostname=False)))
            conn = await ch.get_connection("https", "127.0.0.1", port, f"127.0.0.1:{port}")
            resp = await conn.request(Request(method="GET", target="/", headers=Headers({}), scheme="https", secure=True), streaming=False)
            assert resp.status_code == 200
            assert resp.body == b"final"
        finally:
            await h.drain(timeout=2.0)
            await h.stop()


class TestHTTP3Path:
    async def test_final_response_intact_with_hints(self, h3_loopback):
        lb = h3_loopback(HintCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.status_code == 200
        assert resp.body == b"final"
