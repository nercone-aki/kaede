"""
HTTP trailer field conformance tests.
RFC 9110 §6.5 (trailer semantics, forbidden fields), RFC 9112 §7.1.2 (HTTP/1.1
chunked trailers), RFC 9113 §8.1 / RFC 9114 §4.1 (HTTP/2 & HTTP/3 trailers).
Validated against the RFC specifications, not current Kaede behavior.
"""
from __future__ import annotations

import socket
import asyncio
import ipaddress

from kaede.api.models import Callback, Listener
from kaede.api import server, client
from kaede.http.h1 import H1
from kaede.http.models import Request, Response, Headers
from kaede.http.trailers import build_trailers, is_forbidden_trailer

CLIENT = (ipaddress.IPv4Address("127.0.0.1"), 12345)


def _server_socket() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(socket.SOMAXCONN)
    sock.setblocking(False)
    return sock, sock.getsockname()[1]


async def _stream_body():
    yield b"part1"
    yield b"part2"
    await asyncio.sleep(0)


class TrailerStreamCallback(Callback):
    async def on_request(self, request):
        resp = Response(_stream_body(), content_type="text/plain")
        # Includes a forbidden trailer (Content-Length) that must be stripped.
        resp.trailers = Headers({"X-Checksum": "abc123", "Content-Length": "10"})
        return resp


# ---------------------------------------------------------------------------
# RFC 9110 §6.5.1: forbidden trailer fields
# ---------------------------------------------------------------------------

class TestForbidden:
    def test_framing_forbidden(self):
        assert is_forbidden_trailer("Content-Length")
        assert is_forbidden_trailer("Transfer-Encoding")
        assert is_forbidden_trailer("Host")

    def test_pseudo_header_forbidden(self):
        assert is_forbidden_trailer(":status")

    def test_regular_field_allowed(self):
        assert not is_forbidden_trailer("X-Checksum")
        assert not is_forbidden_trailer("Server-Timing")

    def test_build_trailers_filters(self):
        out = build_trailers([("X-Checksum", "abc"), ("Content-Length", "5"), ("Trailer", "x")])
        assert out is not None
        assert out.get("X-Checksum") == "abc"
        assert "content-length" not in out
        assert "trailer" not in out

    def test_build_trailers_empty(self):
        assert build_trailers([]) is None
        assert build_trailers([("Content-Length", "5")]) is None  # all forbidden -> None
        assert build_trailers(None) is None


# ---------------------------------------------------------------------------
# RFC 9112 §7.1.2: HTTP/1.1 chunked trailers (request side, direct parsing)
# ---------------------------------------------------------------------------

class TestH1RequestTrailers:
    def test_scan_chunked_collects_trailers(self):
        collected: list[tuple[str, str]] = []
        result = H1.scan_chunked(b"5\r\nhello\r\n0\r\nX-A: 1\r\nX-B: 2\r\n\r\n", trailers=collected)
        assert result is not None
        body, _ = result
        assert body == b"hello"
        assert collected == [("X-A", "1"), ("X-B", "2")]

    def test_parse_request_exposes_trailers(self):
        data = (
            b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\nX-Checksum: abc\r\n\r\n"
        )
        req = H1.parse_request(data, client=CLIENT)
        assert req.body == b"hello"
        assert req.trailers is not None
        assert req.trailers.get("X-Checksum") == "abc"

    def test_request_trailers_filter_forbidden(self):
        data = (
            b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n0\r\nContent-Length: 5\r\nX-A: 1\r\n\r\n"
        )
        req = H1.parse_request(data, client=CLIENT)
        assert "content-length" not in req.trailers
        assert req.trailers.get("X-A") == "1"

    def test_non_chunked_request_has_no_trailers(self):
        data = b"POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
        req = H1.parse_request(data, client=CLIENT)
        assert req.trailers is None


class TestH1TrailerBlock:
    def test_build_trailer_block(self):
        assert H1.build_trailer_block(Headers({"X-A": "1"})) == b"x-a: 1\r\n"

    def test_build_trailer_block_rejects_injection(self):
        block = H1.build_trailer_block(Headers({"X-A": "val\r\nInjected: y"}))
        assert b"Injected" not in block


# ---------------------------------------------------------------------------
# HTTP/1.1 response trailers on the wire (raw socket so the chunked framing is
# visible): Trailer header announced, fields after the terminating 0-chunk.
# ---------------------------------------------------------------------------

class TestH1ResponseWire:
    async def _serve(self, callback):
        sock, port = _server_socket()
        cfg = server.Config(bind_http=[], bind_https=[], bind_quic=[], protocols=["http/1.1"])
        h = server.Handler(Listener(sock=sock, kind="http"), callback, cfg)
        await h.start()
        return h, port

    async def test_chunked_trailers_emitted(self):
        h, port = await self._serve(TrailerStreamCallback())
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(-1), timeout=5.0)
            writer.close()
        finally:
            await h.drain(timeout=2.0)
            await h.stop()

        text = data.decode("latin-1").lower()
        assert "transfer-encoding: chunked" in text
        # Trailer header announces the field name (RFC 9112 §7.1.2 / RFC 9110 §6.5.2)
        assert "trailer:" in text.lower()
        # the terminating 0-chunk is followed by the trailer field
        assert "0\r\nx-checksum: abc123\r\n\r\n" in text.lower()
        # forbidden trailer must not be on the wire
        assert "content-length: 10" not in text.lower()


# ---------------------------------------------------------------------------
# Round-trip response trailers through the kaede client for all protocols.
# ---------------------------------------------------------------------------

class TestH1RoundTrip:
    async def test_client_reads_response_trailers(self):
        sock, port = _server_socket()
        cfg = server.Config(bind_http=[], bind_https=[], bind_quic=[], protocols=["http/1.1"])
        h = server.Handler(Listener(sock=sock, kind="http"), TrailerStreamCallback(), cfg)
        await h.start()
        try:
            ch = client.Handler(client.Config(protocols=["http/1.1"]))
            conn = await ch.get_connection("http", "127.0.0.1", port, f"127.0.0.1:{port}")
            resp = await conn.request(Request(method="GET", target="/", headers=Headers({}), scheme="http"), streaming=False)
            assert resp.body == b"part1part2"
            assert resp.trailers is not None
            assert resp.trailers.get("X-Checksum") == "abc123"
            assert "content-length" not in resp.trailers
        finally:
            await h.drain(timeout=2.0)
            await h.stop()


class TestH2RoundTrip:
    async def test_client_reads_response_trailers(self, tls_cert):
        from kaede.tls.models import TLSServerConfig, TLSClientConfig

        certfile, keyfile = tls_cert
        sock, port = _server_socket()
        cfg = server.Config(bind_http=[], bind_https=[], bind_quic=[], protocols=["h2"], tls=TLSServerConfig(certfile=certfile, keyfile=keyfile))
        h = server.Handler(Listener(sock=sock, kind="https"), TrailerStreamCallback(), cfg)
        await h.start()
        try:
            ch = client.Handler(client.Config(protocols=["h2"], tls=TLSClientConfig(verify=False, check_hostname=False)))
            conn = await ch.get_connection("https", "127.0.0.1", port, f"127.0.0.1:{port}")
            resp = await conn.request(Request(method="GET", target="/", headers=Headers({}), scheme="https", secure=True), streaming=False)
            assert resp.body == b"part1part2"
            assert resp.trailers is not None
            assert resp.trailers.get("X-Checksum") == "abc123"
            assert "content-length" not in resp.trailers
        finally:
            await h.drain(timeout=2.0)
            await h.stop()


class TestH3RoundTrip:
    async def test_client_reads_response_trailers(self, h3_loopback):
        lb = h3_loopback(TrailerStreamCallback())
        await lb.handshake()
        resp = await lb.request("GET", "/")
        assert resp.body == b"part1part2"
        assert resp.trailers is not None
        assert resp.trailers.get("X-Checksum") == "abc123"
        assert "content-length" not in resp.trailers
