from __future__ import annotations

import asyncio
import datetime
import ipaddress
import socket
import pytest

from kaede.api.server import Config as ServerConfig, Handler as ServerHandler
from kaede.api.client import Client, Config as ClientConfig
from kaede.models import Callback, Request, Response, Listener
from kaede.tls.models import TLSServerConfig, TLSClientConfig

def _tcp_socket() -> tuple[socket.socket, int]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(socket.SOMAXCONN)
    s.setblocking(False)
    return s, s.getsockname()[1]

def _gen_self_signed() -> tuple[str, str]:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    return cert_pem, key_pem

@pytest.fixture
async def live_server():
    handlers: list[ServerHandler] = []

    async def _start(
        callback: Callback,
        *,
        config: ServerConfig | None = None,
    ) -> int:
        if config is None:
            config = ServerConfig(protocols=["http/1.1"])
        kind = "https" if config.tls.certfile else "http"
        sock, port = _tcp_socket()
        handler = ServerHandler(Listener(sock, kind), callback, config)
        await handler.start()
        handlers.append(handler)
        return port

    yield _start

    for h in handlers:
        try:
            await h.drain(timeout=2.0)
        except Exception:
            pass
        try:
            await h.stop()
        except Exception:
            pass

@pytest.fixture
async def http_client():
    c = Client(ClientConfig(protocols=["http/1.1"]))
    yield c
    await c.close()

@pytest.fixture
def tls_files(tmp_path):
    cert_pem, key_pem = _gen_self_signed()
    cert = tmp_path / "cert.pem"
    key  = tmp_path / "key.pem"
    cert.write_text(cert_pem)
    key.write_text(key_pem)
    return str(cert), str(key)

class TestH1Live:

    async def test_basic_get(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"hello world", status_code=200, content_type="text/plain")

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body == b"hello world"

    async def test_post_body_received(self, live_server, http_client):
        received: list[bytes] = []

        class CB(Callback):
            async def on_request(self, req):
                received.append(req.body or b"")
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        await http_client.post(
            f"http://127.0.0.1:{port}/",
            headers={"Content-Type": "application/octet-stream"},
            body=b"request data",
        )

        assert received == [b"request data"]

    async def test_request_header_forwarded(self, live_server, http_client):
        captured: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                captured.append(req.headers.get("X-Integration-Test") or "")
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        await http_client.get(
            f"http://127.0.0.1:{port}/",
            headers={"X-Integration-Test": "live-value"},
        )

        assert captured == ["live-value"]

    async def test_response_header_forwarded(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                r = Response(b"ok", status_code=200)
                r.headers.set("X-Reply", "reply-value")
                return r

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.headers.get("X-Reply") == "reply-value"

    async def test_custom_status_code(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"not found", status_code=404)

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/missing")

        assert resp.status_code == 404

    async def test_request_target_with_query(self, live_server, http_client):
        targets: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                targets.append(req.target)
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        await http_client.get(f"http://127.0.0.1:{port}/api/resource?key=value&n=42")

        assert targets[-1] == "/api/resource?key=value&n=42"

    async def test_method_get_preserved(self, live_server, http_client):
        methods: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                methods.append(req.method)
                return Response(b"ok")

        port = await live_server(CB())
        await http_client.get(f"http://127.0.0.1:{port}/")
        assert methods[-1] == "GET"

    async def test_method_post_preserved(self, live_server, http_client):
        methods: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                methods.append(req.method)
                return Response(b"ok")

        port = await live_server(CB())
        await http_client.post(f"http://127.0.0.1:{port}/")
        assert methods[-1] == "POST"

    async def test_method_put_preserved(self, live_server, http_client):
        methods: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                methods.append(req.method)
                return Response(b"ok")

        port = await live_server(CB())
        await http_client.put(f"http://127.0.0.1:{port}/")
        assert methods[-1] == "PUT"

    async def test_method_delete_preserved(self, live_server, http_client):
        methods: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                methods.append(req.method)
                return Response(b"ok")

        port = await live_server(CB())
        await http_client.delete(f"http://127.0.0.1:{port}/")
        assert methods[-1] == "DELETE"

    async def test_method_patch_preserved(self, live_server, http_client):
        methods: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                methods.append(req.method)
                return Response(b"ok")

        port = await live_server(CB())
        await http_client.patch(f"http://127.0.0.1:{port}/")
        assert methods[-1] == "PATCH"

    async def test_method_options_preserved(self, live_server, http_client):
        methods: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                methods.append(req.method)
                return Response(b"ok")

        port = await live_server(CB())
        await http_client.options(f"http://127.0.0.1:{port}/")
        assert methods[-1] == "OPTIONS"

    async def test_head_returns_no_body(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"some content", status_code=200, content_type="text/plain")

        port = await live_server(CB())
        resp = await http_client.head(f"http://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body is None

    async def test_callback_exception_returns_500(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                raise RuntimeError("intentional test error")

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.status_code == 500

    async def test_large_response_body(self, live_server, http_client):
        payload = b"a" * (512 * 1024)

        class CB(Callback):
            async def on_request(self, req):
                return Response(payload, status_code=200, content_type="application/octet-stream")

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body == payload

    async def test_large_post_body(self, live_server, http_client):
        payload = bytes(range(256)) * 2000  # 512 KB of varied bytes

        received: list[bytes] = []

        class CB(Callback):
            async def on_request(self, req):
                received.append(req.body or b"")
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        await http_client.post(
            f"http://127.0.0.1:{port}/",
            headers={"Content-Type": "application/octet-stream"},
            body=payload,
        )

        assert received[0] == payload

    async def test_streaming_response(self, live_server):
        chunks = [b"alpha", b"beta", b"gamma"]

        class CB(Callback):
            async def on_request(self, req):
                async def gen():
                    for c in chunks:
                        yield c

                return Response(body=gen(), status_code=200, content_type="application/octet-stream")

        port = await live_server(CB())
        async with Client(ClientConfig(protocols=["http/1.1"], decompress=False)) as c:
            resp = await c.get(f"http://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body == b"".join(chunks)

    async def test_range_request(self, live_server, http_client):
        data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        class CB(Callback):
            async def on_request(self, req):
                return Response(data, status_code=200, content_type="application/octet-stream")

        port = await live_server(CB())
        resp = await http_client.get(
            f"http://127.0.0.1:{port}/",
            headers={"Range": "bytes=0-4"},
        )

        assert resp.status_code == 206
        assert resp.body == b"ABCDE"
        assert "0-4/26" in (resp.headers.get("Content-Range") or "")

    async def test_range_request_suffix(self, live_server, http_client):
        data = b"0123456789"

        class CB(Callback):
            async def on_request(self, req):
                return Response(data, status_code=200, content_type="application/octet-stream")

        port = await live_server(CB())
        resp = await http_client.get(
            f"http://127.0.0.1:{port}/",
            headers={"Range": "bytes=-3"},
        )

        assert resp.status_code == 206
        assert resp.body == b"789"

    async def test_client_ip_populated(self, live_server, http_client):
        captured: list = []

        class CB(Callback):
            async def on_request(self, req):
                captured.append(req.client)
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        await http_client.get(f"http://127.0.0.1:{port}/")

        ip, port_num = captured[0]
        assert isinstance(ip, ipaddress.IPv4Address)
        assert str(ip) == "127.0.0.1"
        assert port_num > 0

    async def test_scheme_is_http(self, live_server, http_client):
        captured: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                captured.append(req.scheme)
                return Response(b"ok")

        port = await live_server(CB())
        await http_client.get(f"http://127.0.0.1:{port}/")

        assert captured == ["http"]

    async def test_server_header_present(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.headers.get("Server") is not None

    async def test_date_header_present(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.headers.get("Date") is not None

    async def test_file_path_response(self, live_server, http_client, tmp_path):
        content = b"file content for live test"
        f = tmp_path / "test.bin"
        f.write_bytes(content)

        class CB(Callback):
            async def on_request(self, req):
                return Response(body=f, status_code=200)

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body == content

    async def test_204_no_body(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                return Response(body=None, status_code=204)

        port = await live_server(CB())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.status_code == 204
        assert resp.body is None

    async def test_keepalive_sequential(self, live_server, http_client):
        counter = [0]

        class CB(Callback):
            async def on_request(self, req):
                counter[0] += 1
                return Response(f"request-{counter[0]}".encode(), status_code=200)

        port = await live_server(CB())
        r1 = await http_client.get(f"http://127.0.0.1:{port}/")
        r2 = await http_client.get(f"http://127.0.0.1:{port}/")
        r3 = await http_client.get(f"http://127.0.0.1:{port}/")

        assert r1.body == b"request-1"
        assert r2.body == b"request-2"
        assert r3.body == b"request-3"

    async def test_concurrent_connections(self, live_server):
        class CB(Callback):
            async def on_request(self, req):
                await asyncio.sleep(0.02)
                return Response(b"ok", status_code=200)

        port = await live_server(CB())

        async def one_req():
            async with Client(ClientConfig(protocols=["http/1.1"])) as c:
                return await c.get(f"http://127.0.0.1:{port}/")

        results = await asyncio.gather(*[one_req() for _ in range(5)])
        assert all(r.status_code == 200 for r in results)

    async def test_default_callback(self, live_server, http_client):
        port = await live_server(Callback())
        resp = await http_client.get(f"http://127.0.0.1:{port}/")
        assert resp.status_code == 200

    async def test_custom_server_name(self, live_server, http_client):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok")

        config = ServerConfig(protocols=["http/1.1"], server_name="TestServer/1.0")
        port = await live_server(CB(), config=config)
        resp = await http_client.get(f"http://127.0.0.1:{port}/")

        assert resp.headers.get("Server") == "TestServer/1.0"

class TestH1Edge:
    async def _send_raw(self, port: int, data: bytes, timeout: float = 3.0) -> bytes:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        try:
            w.write(data)
            await w.drain()
            chunks: list[bytes] = []
            try:
                while True:
                    chunk = await asyncio.wait_for(r.read(4096), timeout=timeout)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except asyncio.TimeoutError:
                pass
            return b"".join(chunks)
        finally:
            w.close()
            try:
                await asyncio.wait_for(w.wait_closed(), timeout=1.0)
            except Exception:
                pass

    async def test_body_too_large_returns_413(self, live_server):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok", status_code=200)

        config = ServerConfig(protocols=["http/1.1"], max_body_size=100)
        port = await live_server(CB(), config=config)

        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: 200\r\n"
            b"\r\n"
        )
        response = await self._send_raw(port, raw)
        assert b"413" in response

    async def test_header_too_large_returns_431(self, live_server):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok", status_code=200)

        config = ServerConfig(protocols=["http/1.1"], max_header_size=200)
        port = await live_server(CB(), config=config)

        big = "x" * 300
        raw = f"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Big: {big}\r\n\r\n".encode()
        response = await self._send_raw(port, raw)
        assert b"431" in response

    async def test_both_te_and_content_length_returns_400(self, live_server):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"5\r\nhello\r\n0\r\n\r\n"
        )
        response = await self._send_raw(port, raw)
        assert b"400" in response

    async def test_unsupported_transfer_encoding_returns_400(self, live_server):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Transfer-Encoding: identity\r\n"
            b"\r\n"
        )
        response = await self._send_raw(port, raw)
        assert b"400" in response

    async def test_chunked_request_body_decoded(self, live_server):
        received: list[bytes] = []

        class CB(Callback):
            async def on_request(self, req):
                received.append(req.body or b"")
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\nhello\r\n"
            b"6\r\n world\r\n"
            b"0\r\n\r\n"
        )
        response = await self._send_raw(port, raw)
        assert b"200" in response
        assert received == [b"hello world"]

    async def test_connection_close_header_closes_after_response(self, live_server):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        raw = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        response = await self._send_raw(port, raw)
        assert b"200" in response

    async def test_incomplete_headers_no_crash(self, live_server):
        class CB(Callback):
            async def on_request(self, req):
                return Response(b"ok", status_code=200)

        port = await live_server(CB())
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"GET / HTTP/1.1\r\nHost: localhost")
        w.close()
        try:
            await asyncio.wait_for(w.wait_closed(), timeout=2.0)
        except Exception:
            pass
        # Server must not crash; just verify we get here

    async def test_pipelined_requests(self, live_server):
        counter = [0]

        class CB(Callback):
            async def on_request(self, req):
                counter[0] += 1
                return Response(f"r{counter[0]}".encode(), status_code=200)

        port = await live_server(CB())
        # Send two requests back-to-back without waiting for the first response
        raw = (
            b"GET /first HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
            b"GET /second HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        )
        response = await self._send_raw(port, raw)
        assert b"r1" in response
        assert b"r2" in response

class TestWebSocketLive:

    async def test_echo_text(self, live_server):
        class CB(Callback):
            async def on_websocket(self, req, ws):
                msg = await asyncio.wait_for(ws.receive(), timeout=5.0)
                if msg is not None:
                    await ws.send(msg)
                await ws.close(1000, "done")

        port = await live_server(CB())
        async with Client(ClientConfig(protocols=["http/1.1"])) as c:
            ws = await c.websocket(f"ws://127.0.0.1:{port}/ws")
            await ws.send("hello websocket")
            reply = await asyncio.wait_for(ws.receive(), timeout=5.0)

        assert reply == b"hello websocket"

    async def test_echo_binary(self, live_server):
        class CB(Callback):
            async def on_websocket(self, req, ws):
                msg = await asyncio.wait_for(ws.receive(), timeout=5.0)
                if msg is not None:
                    await ws.send(msg)
                await ws.close(1000, "done")

        port = await live_server(CB())
        async with Client(ClientConfig(protocols=["http/1.1"])) as c:
            ws = await c.websocket(f"ws://127.0.0.1:{port}/ws")
            await ws.send(b"\x00\x01\x02\x03\xff")
            reply = await asyncio.wait_for(ws.receive(), timeout=5.0)

        assert reply == b"\x00\x01\x02\x03\xff"

    async def test_close_from_server(self, live_server):
        class CB(Callback):
            async def on_websocket(self, req, ws):
                await ws.close(1000, "bye")

        port = await live_server(CB())
        async with Client(ClientConfig(protocols=["http/1.1"])) as c:
            ws = await c.websocket(f"ws://127.0.0.1:{port}/ws")
            sentinel = await asyncio.wait_for(ws.receive(), timeout=5.0)

        assert sentinel is None

    async def test_subprotocol_negotiated(self, live_server):
        agreed: list[str | None] = []

        class CB(Callback):
            def __init__(self):
                super().__init__()
                self.websocket_subprotocols = ["chat", "superchat"]

            async def on_websocket(self, req, ws):
                agreed.append(ws.subprotocol)
                await ws.close(1000, "done")

        port = await live_server(CB())
        async with Client(ClientConfig(protocols=["http/1.1"])) as c:
            ws = await c.websocket(
                f"ws://127.0.0.1:{port}/ws",
                subprotocols=["chat"],
            )
            await asyncio.wait_for(ws.receive(), timeout=5.0)

        assert agreed == ["chat"]

    async def test_request_path_forwarded(self, live_server):
        paths: list[str] = []

        class CB(Callback):
            async def on_websocket(self, req, ws):
                paths.append(req.target)
                await ws.close(1000, "done")

        port = await live_server(CB())
        async with Client(ClientConfig(protocols=["http/1.1"])) as c:
            ws = await c.websocket(f"ws://127.0.0.1:{port}/chat?room=general")
            await asyncio.wait_for(ws.receive(), timeout=5.0)

        assert paths[-1] == "/chat?room=general"

    async def test_multiple_messages(self, live_server):
        class CB(Callback):
            async def on_websocket(self, req, ws):
                for _ in range(5):
                    msg = await asyncio.wait_for(ws.receive(), timeout=3.0)
                    if msg is None:
                        return
                    await ws.send(msg)
                await ws.close(1000, "done")

        port = await live_server(CB())
        async with Client(ClientConfig(protocols=["http/1.1"])) as c:
            ws = await c.websocket(f"ws://127.0.0.1:{port}/ws")
            for i in range(5):
                payload = f"msg{i}".encode()
                await ws.send(payload)
                reply = await asyncio.wait_for(ws.receive(), timeout=3.0)
                assert reply == payload

    async def test_large_message(self, live_server):
        big = b"x" * 65536

        class CB(Callback):
            async def on_websocket(self, req, ws):
                msg = await asyncio.wait_for(ws.receive(), timeout=5.0)
                if msg is not None:
                    await ws.send(msg)
                await ws.close(1000, "done")

        port = await live_server(CB())
        async with Client(ClientConfig(protocols=["http/1.1"])) as c:
            ws = await c.websocket(f"ws://127.0.0.1:{port}/ws")
            await ws.send(big)
            reply = await asyncio.wait_for(ws.receive(), timeout=5.0)

        assert reply == big

class TestHTTPSLive:

    def _tls_client(self, protocols: list[str] | None = None) -> Client:
        return Client(ClientConfig(
            protocols=protocols or ["http/1.1"],
            tls=TLSClientConfig(verify=False, check_hostname=False),
        ))

    async def test_basic_get(self, live_server, tls_files):
        cert, key = tls_files

        class CB(Callback):
            async def on_request(self, req):
                return Response(b"secure hello", status_code=200, content_type="text/plain")

        config = ServerConfig(
            protocols=["http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._tls_client() as c:
            resp = await c.get(f"https://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body == b"secure hello"

    async def test_post_body_received(self, live_server, tls_files):
        cert, key = tls_files
        received: list[bytes] = []

        class CB(Callback):
            async def on_request(self, req):
                received.append(req.body or b"")
                return Response(b"ok", status_code=200)

        config = ServerConfig(
            protocols=["http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._tls_client() as c:
            await c.post(
                f"https://127.0.0.1:{port}/",
                headers={"Content-Type": "application/octet-stream"},
                body=b"encrypted payload",
            )

        assert received == [b"encrypted payload"]

    async def test_large_response(self, live_server, tls_files):
        cert, key = tls_files
        payload = b"Z" * (256 * 1024)

        class CB(Callback):
            async def on_request(self, req):
                return Response(payload, status_code=200, content_type="application/octet-stream")

        config = ServerConfig(
            protocols=["http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._tls_client() as c:
            resp = await c.get(f"https://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body == payload

    async def test_request_headers_forwarded(self, live_server, tls_files):
        cert, key = tls_files
        captured: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                captured.append(req.headers.get("X-Secure") or "")
                return Response(b"ok", status_code=200)

        config = ServerConfig(
            protocols=["http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._tls_client() as c:
            await c.get(
                f"https://127.0.0.1:{port}/",
                headers={"X-Secure": "tls-value"},
            )

        assert captured == ["tls-value"]

    async def test_scheme_is_https(self, live_server, tls_files):
        cert, key = tls_files
        captured: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                captured.append(req.scheme)
                return Response(b"ok")

        config = ServerConfig(
            protocols=["http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._tls_client() as c:
            await c.get(f"https://127.0.0.1:{port}/")

        assert captured == ["https"]

    async def test_concurrent_tls_connections(self, live_server, tls_files):
        cert, key = tls_files

        class CB(Callback):
            async def on_request(self, req):
                await asyncio.sleep(0.02)
                return Response(b"ok", status_code=200)

        config = ServerConfig(
            protocols=["http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async def one_req():
            async with self._tls_client() as c:
                return await c.get(f"https://127.0.0.1:{port}/")

        results = await asyncio.gather(*[one_req() for _ in range(4)])
        assert all(r.status_code == 200 for r in results)

class TestH2Live:

    def _h2_client(self) -> Client:
        return Client(ClientConfig(
            protocols=["h2", "http/1.1"],
            tls=TLSClientConfig(verify=False, check_hostname=False),
        ))

    async def test_basic_get(self, live_server, tls_files):
        cert, key = tls_files

        class CB(Callback):
            async def on_request(self, req):
                return Response(b"http2 response", status_code=200, content_type="text/plain")

        config = ServerConfig(
            protocols=["h2", "http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._h2_client() as c:
            resp = await c.get(f"https://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body == b"http2 response"

    async def test_concurrent_streams(self, live_server, tls_files):
        cert, key = tls_files

        class CB(Callback):
            async def on_request(self, req):
                await asyncio.sleep(0.01)
                return Response(b"ok", status_code=200)

        config = ServerConfig(
            protocols=["h2", "http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._h2_client() as c:
            results = await asyncio.gather(*[
                c.get(f"https://127.0.0.1:{port}/") for _ in range(5)
            ])

        assert all(r.status_code == 200 for r in results)

    async def test_post_body(self, live_server, tls_files):
        cert, key = tls_files
        received: list[bytes] = []

        class CB(Callback):
            async def on_request(self, req):
                received.append(req.body or b"")
                return Response(b"ok", status_code=200)

        config = ServerConfig(
            protocols=["h2", "http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._h2_client() as c:
            await c.post(
                f"https://127.0.0.1:{port}/",
                headers={"Content-Type": "application/octet-stream"},
                body=b"h2 post body",
            )

        assert received == [b"h2 post body"]

    async def test_large_response(self, live_server, tls_files):
        cert, key = tls_files
        payload = b"H" * (256 * 1024)

        class CB(Callback):
            async def on_request(self, req):
                return Response(payload, status_code=200, content_type="application/octet-stream")

        config = ServerConfig(
            protocols=["h2", "http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._h2_client() as c:
            resp = await c.get(f"https://127.0.0.1:{port}/")

        assert resp.status_code == 200
        assert resp.body == payload

    async def test_protocol_is_h2(self, live_server, tls_files):
        cert, key = tls_files
        captured: list[str] = []

        class CB(Callback):
            async def on_request(self, req):
                captured.append(req.protocol)
                return Response(b"ok")

        config = ServerConfig(
            protocols=["h2", "http/1.1"],
            tls=TLSServerConfig(certfile=cert, keyfile=key),
        )
        port = await live_server(CB(), config=config)

        async with self._h2_client() as c:
            await c.get(f"https://127.0.0.1:{port}/")

        assert captured == ["HTTP/2.0"]
