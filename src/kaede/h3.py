from __future__ import annotations

import os
import asyncio
import ipaddress
from dataclasses import dataclass

from aioquic.h3.connection import H3Connection
from aioquic.h3.events import HeadersReceived, DataReceived
from aioquic.quic.connection import QuicConnection

from .models import Request, Response, Headers, RequestStream, ResponseStream
from .tls import TLSInfo

H3_FORBIDDEN_HEADERS = ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection")

@dataclass
class H3Info:
    connection_id: bytes
    stream_id: int

@dataclass
class H3WSUpgrade:
    stream_id: int
    request: Request

class H3:
    def __init__(self, quic: QuicConnection, connection_id: bytes = b"", max_body_size: int = 16 * 1024 * 1024):
        self.quic = quic
        self.connection = H3Connection(quic)
        self.connection_id = connection_id

        self.request_streams: dict[int, RequestStream] = {}
        self.response_streams: dict[int, ResponseStream] = {}
        self.websocket_streams: dict[int, asyncio.Queue[bytes | None]] = {}

        self.max_body_size = max_body_size

    def handle_event(self, quic_event, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], secure: bool = True, tls: TLSInfo | None = None) -> tuple[list[Request], list[H3WSUpgrade]]:
        completed: list[Request] = []
        websocket_upgrades: list[H3WSUpgrade] = []

        for event in self.connection.handle_event(quic_event):
            if isinstance(event, HeadersReceived):
                stream = RequestStream()
                websocket_protocol: str | None = None

                for nameb, valueb in event.headers:
                    name = nameb.decode("ascii") if isinstance(nameb, (bytes, bytearray)) else nameb
                    value = valueb.decode("utf-8") if isinstance(valueb, (bytes, bytearray)) else valueb

                    if name == ":method":
                        stream.method = value
                    elif name == ":path":
                        stream.target = value
                    elif name == ":authority":
                        stream.authority = value
                        stream.headers.append("host", value)
                    elif name == ":protocol":
                        websocket_protocol = value
                    elif not name.startswith(":"):
                        stream.headers.append(name, value)

                if stream.method == "CONNECT" and websocket_protocol == "websocket":
                    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
                    self.websocket_streams[event.stream_id] = queue
                    request = Request(client=client, scheme="https", secure=secure, protocol="HTTP/3.0", method="GET", target=stream.target, headers=stream.headers, body=None, h2=None, h3=H3Info(connection_id=self.connection_id, stream_id=event.stream_id), tls=tls)
                    websocket_upgrades.append(H3WSUpgrade(stream_id=event.stream_id, request=request))
                    continue

                self.request_streams[event.stream_id] = stream
                if event.stream_ended:
                    completed.append(self.finalize(event.stream_id, client, secure, tls))

            elif isinstance(event, DataReceived):
                if event.stream_id in self.websocket_streams:
                    if event.data:
                        self.websocket_streams[event.stream_id].put_nowait(event.data)

                    if event.stream_ended:
                        self.websocket_streams[event.stream_id].put_nowait(None)
                        del self.websocket_streams[event.stream_id]

                else:
                    stream = self.request_streams.get(event.stream_id)

                    if stream is not None:
                        stream.body.extend(event.data)

                    if stream is not None and len(stream.body) > self.max_body_size:
                        self.request_streams.pop(event.stream_id, None)
                        try:
                            self.quic.reset_stream(event.stream_id, error_code=0x10C)
                        except Exception:
                            pass

                    elif event.stream_ended and event.stream_id in self.request_streams:
                        completed.append(self.finalize(event.stream_id, client, secure, tls))

        return completed, websocket_upgrades

    def finalize(self, stream_id: int, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], secure: bool, tls: TLSInfo | None) -> Request:
        stream = self.request_streams.pop(stream_id)
        body = bytes(stream.body) if stream.body else None
        return Request(client=client, scheme="https", secure=secure, protocol="HTTP/3.0", method=stream.method, target=stream.target, headers=stream.headers, body=body, h2=None, h3=H3Info(connection_id=self.connection_id, stream_id=stream_id), tls=tls)

    def send(self, stream_id: int, response: Response) -> os.PathLike | None:
        headers = self.build_headers(response)

        if response.has_real_body:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            self.connection.send_data(stream_id, response.body, end_stream=True)
            return None

        elif response.body is not None:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            return response.body

        else:
            self.connection.send_headers(stream_id, headers, end_stream=True)
            return None

    def build_headers(self, response: Response) -> list[tuple[bytes, bytes]]:
        headers: list[tuple[bytes, bytes]] = [(b":status", str(response.status_code).encode("ascii"))]
        for name, value in response.headers.items():
            lname = name.lower()

            if lname in H3_FORBIDDEN_HEADERS:
                continue

            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue

            headers.append((lname.encode("ascii"), value.encode("utf-8")))

        return headers

    def send_headers_only(self, stream_id: int, response: Response):
        self.connection.send_headers(stream_id, self.build_headers(response), end_stream=False)

    def send_chunk(self, stream_id: int, chunk: bytes, end_stream: bool):
        self.connection.send_data(stream_id, chunk, end_stream=end_stream)

    def ws_accept(self, stream_id: int, subprotocol: str | None = None, extensions: str | None = None):
        headers: list[tuple[bytes, bytes]] = [(b":status", b"200")]
        if subprotocol:
            headers.append((b"sec-websocket-protocol", subprotocol.encode()))
        if extensions:
            headers.append((b"sec-websocket-extensions", extensions.encode()))
        self.connection.send_headers(stream_id, headers, end_stream=False)

    def websocket_send(self, stream_id: int, data: bytes):
        self.connection.send_data(stream_id, data, end_stream=False)

    def websocket_close(self, stream_id: int):
        self.websocket_streams.pop(stream_id, None)
        try:
            self.connection.send_data(stream_id, b"", end_stream=True)
        except Exception:
            pass

    def build_request_headers(self, request: Request, authority: str) -> list[tuple[bytes, bytes]]:
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

    def send_request(self, request: Request, authority: str) -> int:
        stream_id = self.quic.get_next_available_stream_id()
        headers = self.build_request_headers(request, authority)
        has_body = bool(request.body)

        self.connection.send_headers(stream_id, headers, end_stream=not has_body)

        if has_body:
            self.connection.send_data(stream_id, request.body, end_stream=True)

        return stream_id

    def send_connect_websocket(self, request: Request, authority: str, subprotocols: list[str] | None = None, extensions: str | None = None) -> int:
        stream_id = self.quic.get_next_available_stream_id()

        headers: list[tuple[bytes, bytes]] = [
            (b":method", b"CONNECT"),
            (b":protocol", b"websocket"),
            (b":scheme", request.scheme.encode("ascii")),
            (b":authority", authority.encode("ascii")),
            (b":path", request.target.encode("latin-1")),
            (b"sec-websocket-version", b"13"),
        ]
        if subprotocols:
            headers.append((b"sec-websocket-protocol", ", ".join(subprotocols).encode()))
        if extensions:
            headers.append((b"sec-websocket-extensions", extensions.encode()))

        for name, value in request.headers.items():
            lname = name.lower()
            if lname in H3_FORBIDDEN_HEADERS or lname in ("host", "content-length") or lname.startswith("sec-websocket"):
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname.encode("ascii"), value.encode("utf-8")))

        self.connection.send_headers(stream_id, headers, end_stream=False)

        queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.websocket_streams[stream_id] = queue

        return stream_id

    def send_body_chunk(self, stream_id: int, chunk: bytes, end_stream: bool):
        self.connection.send_data(stream_id, chunk, end_stream=end_stream)

    def handle_event_client(self, quic_event) -> list[tuple]:
        out_events: list[tuple] = []

        for event in self.connection.handle_event(quic_event):
            if isinstance(event, HeadersReceived):
                status = 0
                headers = Headers({})
                for nameb, valueb in event.headers:
                    name = nameb.decode("ascii") if isinstance(nameb, (bytes, bytearray)) else nameb
                    value = valueb.decode("utf-8") if isinstance(valueb, (bytes, bytearray)) else valueb

                    if name == ":status":
                        try:
                            status = int(value)
                        except ValueError:
                            status = 0
                    elif not name.startswith(":"):
                        headers.append(name, value)

                out_events.append(("response", event.stream_id, status, headers))
                if event.stream_ended:
                    out_events.append(("end", event.stream_id))

            elif isinstance(event, DataReceived):
                if event.stream_id in self.websocket_streams:
                    if event.data:
                        self.websocket_streams[event.stream_id].put_nowait(event.data)
                    if event.stream_ended:
                        self.websocket_streams[event.stream_id].put_nowait(None)
                        del self.websocket_streams[event.stream_id]

                else:
                    if event.data:
                        out_events.append(("data", event.stream_id, event.data))
                    if event.stream_ended:
                        out_events.append(("end", event.stream_id))

        return out_events
