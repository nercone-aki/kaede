from __future__ import annotations

import os
import asyncio
import ipaddress

from ..http.h3 import H3, HeadersReceived, DataReceived, H3_FORBIDDEN_HEADERS, H3Info
from ..models import Request, Response, Headers
from ..process import process_request
from ..quic import QuicConnection, HandshakeCompleted, StreamDataReceived, StreamReset, ConnectionTerminated
from ..tls.quic_tls import QuicTLS
from .common import StreamState, consume_response

def peername(addr) -> tuple:
    try:
        return (ipaddress.ip_address(addr[0]), int(addr[1]))
    except (ValueError, IndexError, TypeError):
        return (ipaddress.IPv4Address("0.0.0.0"), 0)

def build_response_headers(response: Response) -> list[tuple[bytes, bytes]]:
    headers: list[tuple[bytes, bytes]] = [(b":status", str(response.status_code).encode("ascii"))]
    for name, value in response.headers.items():
        lname = name.lower()
        if lname in H3_FORBIDDEN_HEADERS:
            continue
        if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
            continue
        headers.append((lname.encode("ascii"), value.encode("utf-8")))
    return headers

def build_request_headers(request: Request, authority: str) -> list[tuple[bytes, bytes]]:
    headers: list[tuple[bytes, bytes]] = [
        (b":method", request.method.encode("ascii")),
        (b":scheme", request.scheme.encode("ascii")),
        (b":authority", authority.encode("ascii")),
        (b":path", request.target.encode("latin-1")),
    ]
    for name, value in request.headers.items():
        lname = name.lower()
        if lname in H3_FORBIDDEN_HEADERS or lname in ("host", "content-length"):
            continue
        if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
            continue
        headers.append((lname.encode("ascii"), value.encode("utf-8")))
    return headers

class _RequestAssembler:
    def __init__(self):
        self.headers: list[tuple[bytes, bytes]] | None = None
        self.body = bytearray()
        self.too_large = False

class ServerConnection:
    def __init__(self, protocol: "QuicServerProtocol", quic: QuicConnection, addr):
        self.protocol = protocol
        self.handler = protocol.handler
        self.quic = quic
        self.addr = addr
        self.h3 = H3(quic, is_client=False, max_body_size=self.handler.config.max_body_size)
        self.client = peername(addr)
        self.tls = None
        self.assemblers: dict[int, _RequestAssembler] = {}
        self._timer: asyncio.TimerHandle | None = None

    def handle_datagram(self, data: bytes) -> bool:
        self.quic.receive_datagram(data, self.protocol.now())
        events = self.quic.events()
        terminated = False

        for event in events:
            if isinstance(event, HandshakeCompleted):
                if self.tls is None:
                    self.tls = self.quic.tls.info()

            elif isinstance(event, ConnectionTerminated):
                terminated = True

        self.feed_h3(events)
        self.flush()

        return terminated

    def feed_h3(self, quic_events: list):
        for ev in self.h3.feed(quic_events):
            if isinstance(ev, HeadersReceived):
                asm = self.assemblers.setdefault(ev.stream_id, _RequestAssembler())
                asm.headers = ev.headers

            elif isinstance(ev, DataReceived):
                asm = self.assemblers.get(ev.stream_id)

                if asm is None:
                    continue

                if ev.data:
                    asm.body.extend(ev.data)

                    if len(asm.body) > self.handler.config.max_body_size:
                        asm.too_large = True

                if ev.stream_ended:
                    self.dispatch(ev.stream_id, asm)

    def dispatch(self, stream_id: int, asm: _RequestAssembler):
        self.assemblers.pop(stream_id, None)
        if asm.headers is None:
            return
        if asm.too_large:
            self.h3.send_headers(stream_id, [(b":status", b"413")], end_stream=True)
            self.flush()
            return
        request = self.build_request(stream_id, asm)
        self.handler.create_task(self.respond(request))

    def build_request(self, stream_id: int, asm: _RequestAssembler) -> Request:
        method = "GET"
        target = "/"
        authority = ""
        headers = Headers({})

        for nameb, valueb in asm.headers:
            name = nameb.decode("ascii", "replace") if isinstance(nameb, (bytes, bytearray)) else nameb
            value = valueb.decode("utf-8", "replace") if isinstance(valueb, (bytes, bytearray)) else valueb

            if name == ":method":
                method = value

            elif name == ":path":
                target = value

            elif name == ":authority":
                authority = value
                headers.append("host", value)

            elif not name.startswith(":"):
                headers.append(name, value)

        body = bytes(asm.body) if asm.body else None

        return Request(client=self.client, scheme="https", secure=True, protocol="HTTP/3.0", method=method, target=target, headers=headers, body=body, h2=None, h3=H3Info(connection_id=self.quic.local_cid, stream_id=stream_id), tls=self.tls)

    async def respond(self, request: Request):
        if request.h3 is None:
            return

        stream_id = request.h3.stream_id
        response = await process_request(request, callback=self.handler.callback, config=self.handler.config)

        if response.is_streaming:
            await self.stream(stream_id, response)
            return

        headers = build_response_headers(response)

        if response.has_real_body:
            self.h3.send_headers(stream_id, headers, end_stream=False)
            self.h3.send_data(stream_id, response.body, end_stream=True)

        elif response.body is not None:
            self.h3.send_headers(stream_id, headers, end_stream=False)
            await self.send_file(stream_id, response.body, response.file_range)

        else:
            self.h3.send_headers(stream_id, headers, end_stream=True)

        self.flush()

    async def stream(self, stream_id: int, response: Response):
        self.h3.send_headers(stream_id, build_response_headers(response), end_stream=False)
        self.flush()

        try:
            async for chunk in response.body:
                if chunk:
                    self.h3.send_data(stream_id, chunk, end_stream=False)
                    self.flush()
        finally:
            self.h3.send_data(stream_id, b"", end_stream=True)
            self.flush()

    async def send_file(self, stream_id: int, path: os.PathLike, file_range: tuple[int, int] | None = None):
        loop = asyncio.get_running_loop()

        try:
            fp = await loop.run_in_executor(None, lambda: open(os.fspath(path), "rb"))
        except OSError:
            self.h3.send_data(stream_id, b"", end_stream=True)
            self.flush()
            return

        try:
            remaining = None

            if file_range is not None:
                start, end = file_range
                await loop.run_in_executor(None, fp.seek, start)
                remaining = end - start + 1

            pending = await loop.run_in_executor(None, fp.read, 65536 if remaining is None else min(65536, remaining))

            while pending:
                if remaining is not None:
                    remaining -= len(pending)

                size = 65536 if remaining is None else min(65536, remaining)
                nxt = await loop.run_in_executor(None, fp.read, size) if size > 0 else b""
                self.h3.send_data(stream_id, pending, end_stream=not nxt)
                self.flush()
                pending = nxt

        finally:
            await loop.run_in_executor(None, fp.close)

    def flush(self):
        now = self.protocol.now()
        for data, _ in self.quic.datagrams_to_send(now):
            self.protocol.transport.sendto(data, self.addr)
        self.schedule_timer()

    def schedule_timer(self):
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        when = self.quic.get_timer()
        if when is not None:
            loop = asyncio.get_running_loop()
            self._timer = loop.call_at(loop.time() + max(0.0, when - self.protocol.now()), self.on_timer)

    def on_timer(self):
        self._timer = None
        self.quic.handle_timer(self.protocol.now())
        self.flush()

class QuicServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler):
        self.handler = handler
        self.transport: asyncio.DatagramTransport | None = None
        self.connections: dict[tuple, ServerConnection] = {}
        self.epoch = 0.0

    def now(self) -> float:
        return asyncio.get_running_loop().time()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        if self.handler.shutdown:
            return
        conn = self.connections.get(addr)
        if conn is None:
            if not data or not (data[0] & 0x80):
                return
            try:
                quic = QuicConnection.create_server(data, lambda tp: QuicTLS.for_server(self.handler.config.tls, transport_params=tp))
            except Exception:
                return
            conn = ServerConnection(self, quic, addr)
            self.connections[addr] = conn

        if conn.handle_datagram(data):
            self.connections.pop(addr, None)

    def error_received(self, exc):
        pass

class ClientConnection:
    def __init__(self, transport, quic: QuicConnection, authority: str, handler):
        self.transport = transport
        self.quic = quic
        self.authority = authority
        self.handler = handler
        self.h3 = H3(quic, is_client=True, max_body_size=(handler.config.max_body_size if handler else 16 * 1024 * 1024))
        self.addr = None
        self.streams: dict[int, StreamState] = {}
        self.headers_seen: dict[int, bool] = {}
        self.multiplexed = True
        self.closed = False
        self.timer: asyncio.TimerHandle | None = None
        self.connected: asyncio.Future = asyncio.get_running_loop().create_future()

    def now(self) -> float:
        return asyncio.get_running_loop().time()

    def datagram_received(self, data: bytes):
        self.quic.receive_datagram(data, self.now())
        events = self.quic.events()

        for ev in events:
            if isinstance(ev, HandshakeCompleted) and not self.connected.done():
                self.connected.set_result(None)

            elif isinstance(ev, ConnectionTerminated):
                self.fail_all(ConnectionError("connection terminated"))

        for h3ev in self.h3.feed(events):
            self.on_h3_event(h3ev)

        self.flush()

    def on_h3_event(self, ev):
        state = self.streams.get(ev.stream_id)

        if state is None:
            return

        if isinstance(ev, HeadersReceived):
            status = 0
            headers = Headers({})

            for nameb, valueb in ev.headers:
                name = nameb.decode("ascii", "replace") if isinstance(nameb, (bytes, bytearray)) else nameb
                value = valueb.decode("utf-8", "replace") if isinstance(valueb, (bytes, bytearray)) else valueb

                if name == ":status":
                    try:
                        status = int(value)
                    except ValueError:
                        status = 0

                elif not name.startswith(":"):
                    headers.append(name, value)

            state.set_headers(status, headers)

        elif isinstance(ev, DataReceived):
            if ev.data:
                state.push(ev.data)

            if ev.stream_ended:
                state.finish()

    def fail_all(self, exc: BaseException):
        self.closed = True
        if not self.connected.done():
            self.connected.set_exception(exc)
        for state in list(self.streams.values()):
            state.fail(exc)

    def is_open(self) -> bool:
        return not self.closed

    async def request(self, request: Request, streaming: bool) -> Response:
        read_timeout = self.handler.config.read_timeout if self.handler else 60
        stream_id = self.h3.open_request_stream()
        headers = build_request_headers(request, self.authority)
        has_body = bool(request.body)
        self.h3.send_headers(stream_id, headers, end_stream=not has_body)

        if has_body:
            self.h3.send_data(stream_id, request.body, end_stream=True)

        state = StreamState(asyncio.get_running_loop(), self.handler.config.max_body_size if self.handler else None)

        self.streams[stream_id] = state
        self.flush()

        def on_done():
            self.streams.pop(stream_id, None)

        try:
            return await consume_response(state, streaming, "HTTP/3.0", read_timeout, on_done)
        except BaseException:
            self.streams.pop(stream_id, None)
            raise

    def flush(self):
        for data, _ in self.quic.datagrams_to_send(self.now()):
            if self.transport is not None:
                self.transport.sendto(data, self.addr)
        self.schedule_timer()

    def schedule_timer(self):
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

        when = self.quic.get_timer()

        if when is not None:
            loop = asyncio.get_running_loop()
            self.timer = loop.call_at(loop.time() + max(0.0, when - self.now()), self.on_timer)

    def on_timer(self):
        self.timer = None
        self.quic.handle_timer(self.now())
        self.flush()

    def close(self):
        self.closed = True

        if self.timer is not None:
            self.timer.cancel()
            self.timer = None

        if self.transport is not None:
            self.transport.close()

    async def aclose(self):
        self.close()

class ClientDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self, connection: ClientConnection):
        self.connection = connection

    def connection_made(self, transport):
        self.connection.transport = transport

    def datagram_received(self, data, addr):
        self.connection.datagram_received(data)

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        self.connection.fail_all(exc or ConnectionError("connection lost"))

async def connect_quic(handler, host: str, port: int, authority: str, *, server_name: str, tls_config, connect_timeout: float) -> ClientConnection:
    loop = asyncio.get_running_loop()
    quic = QuicConnection.create_client(lambda tp: QuicTLS.for_client(tls_config, server_name, transport_params=tp), server_name)
    conn = ClientConnection(None, quic, authority, handler)

    transport, _ = await loop.create_datagram_endpoint(lambda: ClientDatagramProtocol(conn), remote_addr=(host, port))

    conn.transport = transport
    conn.addr = None
    conn.flush()

    await asyncio.wait_for(conn.connected, timeout=connect_timeout)

    return conn
