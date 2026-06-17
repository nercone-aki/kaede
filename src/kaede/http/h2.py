from __future__ import annotations

import os
import asyncio
import ipaddress
from typing import Literal
from dataclasses import dataclass

import h2.config
import h2.connection
import h2.errors
import h2.events
from h2.settings import SettingCodes

from ..models import Request, Response, Headers, RequestStream, ResponseStream
from ..tls import TLSInfo

H2_FORBIDDEN_HEADERS = ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection")

@dataclass
class H2Info:
    connection_id: bytes
    stream_id: int

@dataclass
class H2WSUpgrade:
    stream_id: int
    request: Request

class H2:
    def __init__(self, connection_id: bytes = b"", max_body_size: int = 16 * 1024 * 1024, max_stream_resets: int = 1000, max_concurrent_streams: int = 100, client_side: bool = False):
        self.connection_id = connection_id
        self.client_side = client_side
        self.connection = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=client_side, header_encoding="utf-8"))

        self.request_streams: dict[int, RequestStream] = {}
        self.response_streams: dict[int, ResponseStream] = {}
        self.websocket_streams: dict[int, asyncio.Queue[bytes | None]] = {}

        self.reset_count = 0

        self.max_body_size = max_body_size
        self.max_stream_resets = max_stream_resets
        self.max_concurrent_streams = max_concurrent_streams

        self.send_buffers: dict[int, bytearray] = {}
        self.send_ended: dict[int, bool] = {}

        self.flow_control_event = asyncio.Event()

    def initiate(self) -> bytes:
        self.connection.initiate_connection()
        if self.client_side:
            self.connection.update_settings({SettingCodes.MAX_CONCURRENT_STREAMS: self.max_concurrent_streams})
        else:
            self.connection.update_settings({SettingCodes.ENABLE_CONNECT_PROTOCOL: 1, SettingCodes.MAX_CONCURRENT_STREAMS: self.max_concurrent_streams})
        return self.connection.data_to_send()

    def receive(self, data: bytes, *, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], scheme: Literal["http", "https"] = "https", secure: bool = True, tls: TLSInfo | None = None) -> tuple[bytes, list[Request], list[H2WSUpgrade], bool]:
        closed = False
        events = self.connection.receive_data(data)
        completed: list[Request] = []
        websocket_upgrades: list[H2WSUpgrade] = []

        for event in events:
            if isinstance(event, h2.events.RequestReceived):
                stream = RequestStream(scheme=scheme)
                websocket_protocol: str | None = None

                for name, value in event.headers:
                    if name == ":method":
                        stream.method = value
                    elif name == ":path":
                        stream.target = value
                    elif name == ":scheme":
                        stream.scheme = value
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
                    request = Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/2.0", method="GET", target=stream.target, headers=stream.headers, body=None, h2=H2Info(connection_id=self.connection_id, stream_id=event.stream_id), h3=None, tls=tls)
                    websocket_upgrades.append(H2WSUpgrade(stream_id=event.stream_id, request=request))
                    continue

                self.request_streams[event.stream_id] = stream
                if event.stream_ended:
                    completed.append(self.finalize_request(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id in self.websocket_streams:
                    if event.data:
                        self.websocket_streams[event.stream_id].put_nowait(event.data)

                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    if event.stream_ended:
                        self.websocket_streams[event.stream_id].put_nowait(None)
                        del self.websocket_streams[event.stream_id]

                else:
                    stream = self.request_streams.get(event.stream_id)
                    if stream is not None:
                        stream.body.extend(event.data)

                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    if stream is not None and len(stream.body) > self.max_body_size:
                        self.request_streams.pop(event.stream_id, None)

                        try:
                            self.connection.reset_stream(event.stream_id, error_code=h2.errors.ErrorCodes.ENHANCE_YOUR_CALM)
                        except Exception:
                            pass

                    elif event.stream_ended and event.stream_id in self.request_streams:
                        completed.append(self.finalize_request(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id in self.websocket_streams:
                    self.websocket_streams[event.stream_id].put_nowait(None)
                    del self.websocket_streams[event.stream_id]

                elif event.stream_id in self.request_streams:
                    completed.append(self.finalize_request(event.stream_id, client, secure, tls))

            elif isinstance(event, h2.events.StreamReset):
                self.reset_count += 1

                if self.reset_count > self.max_stream_resets:
                    closed = True

                if event.stream_id in self.websocket_streams:
                    self.websocket_streams[event.stream_id].put_nowait(None)
                    del self.websocket_streams[event.stream_id]

                else:
                    self.request_streams.pop(event.stream_id, None)

                self.discard_send(event.stream_id)

            elif isinstance(event, h2.events.WindowUpdated):
                if event.stream_id == 0:
                    for sid in list(self.send_buffers.keys()):
                        self.pump(sid)
                else:
                    self.pump(event.stream_id)

            elif isinstance(event, h2.events.ConnectionTerminated):
                for queue in self.websocket_streams.values():
                    queue.put_nowait(None)

                self.websocket_streams.clear()
                self.request_streams.clear()
                self.send_buffers.clear()
                self.send_ended.clear()

                closed = True

        for sid in list(self.send_buffers.keys()):
            self.pump(sid)

        self.flow_control_event.set()

        return self.connection.data_to_send(), completed, websocket_upgrades, closed

    def enqueue(self, stream_id: int, data: bytes, end_stream: bool):
        buffer = self.send_buffers.get(stream_id)

        if buffer is None:
            buffer = bytearray()
            self.send_buffers[stream_id] = buffer

        buffer.extend(data)

        if end_stream:
            self.send_ended[stream_id] = True

    def discard_send(self, stream_id: int):
        self.send_buffers.pop(stream_id, None)
        self.send_ended.pop(stream_id, None)

    def pump(self, stream_id: int):
        buffer = self.send_buffers.get(stream_id)
        ended = self.send_ended.get(stream_id, False)

        if buffer is None:
            if ended:
                try:
                    self.connection.end_stream(stream_id)
                except Exception:
                    pass
                self.send_ended.pop(stream_id, None)
            return

        try:
            while buffer:
                window = self.connection.local_flow_control_window(stream_id)
                if window <= 0:
                    return

                max_frame = self.connection.max_outbound_frame_size or 16384
                size = min(len(buffer), window, max_frame)

                chunk = bytes(buffer[:size])
                del buffer[:size]

                end = ended and not buffer
                self.connection.send_data(stream_id, chunk, end_stream=end)

                if end:
                    self.discard_send(stream_id)
                    return

            if ended:
                self.connection.end_stream(stream_id)
                self.discard_send(stream_id)

        except Exception:
            self.discard_send(stream_id)

    def stream_buffered(self, stream_id: int) -> int:
        buf = self.send_buffers.get(stream_id)
        return len(buf) if buf else 0

    def build_response_headers(self, response: Response) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = [(":status", str(response.status_code))]

        for name, value in response.headers.items():
            lname = name.lower()

            if lname in H2_FORBIDDEN_HEADERS:
                continue

            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue

            headers.append((lname, value))

        return headers

    def finalize_request(self, stream_id: int, client: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int], secure: bool, tls: TLSInfo | None) -> Request:
        stream = self.request_streams.pop(stream_id)
        body = bytes(stream.body) if stream.body else None
        return Request(client=client, scheme=stream.scheme if stream.scheme in ("http", "https") else "https", secure=secure, protocol="HTTP/2.0", method=stream.method, target=stream.target, headers=stream.headers, body=body, h2=H2Info(connection_id=self.connection_id, stream_id=stream_id), h3=None, tls=tls)

    def send_response(self, stream_id: int, response: Response) -> tuple[bytes, os.PathLike | None]:
        headers = self.build_response_headers(response)

        if response.has_real_body:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            self.enqueue(stream_id, response.body, end_stream=True)
            self.pump(stream_id)
            return self.connection.data_to_send(), None

        elif response.body is not None:
            self.connection.send_headers(stream_id, headers, end_stream=False)
            return self.connection.data_to_send(), response.body

        else:
            self.connection.send_headers(stream_id, headers, end_stream=True)
            return self.connection.data_to_send(), None

    def send_response_headers(self, stream_id: int, response: Response) -> bytes:
        self.connection.send_headers(stream_id, self.build_response_headers(response), end_stream=False)
        return self.connection.data_to_send()

    def send_chunk(self, stream_id: int, chunk: bytes, end_stream: bool) -> bytes:
        self.enqueue(stream_id, chunk, end_stream)
        self.pump(stream_id)
        return self.connection.data_to_send()

    def close(self, error_code: int = 0) -> bytes:
        self.connection.close_connection(error_code=error_code)
        return self.connection.data_to_send()

    def websocket_accept(self, stream_id: int, subprotocol: str | None = None, extensions: str | None = None) -> bytes:
        headers = [(":status", "200")]

        if subprotocol:
            headers.append(("sec-websocket-protocol", subprotocol))

        if extensions:
            headers.append(("sec-websocket-extensions", extensions))

        self.connection.send_headers(stream_id, headers, end_stream=False)
        return self.connection.data_to_send()

    def websocket_send(self, stream_id: int, data: bytes) -> bytes:
        self.enqueue(stream_id, data, end_stream=False)
        self.pump(stream_id)
        return self.connection.data_to_send()

    def websocket_close(self, stream_id: int) -> bytes:
        self.websocket_streams.pop(stream_id, None)
        self.send_ended[stream_id] = True
        self.pump(stream_id)
        return self.connection.data_to_send()

    def build_request_headers(self, request: Request, authority: str) -> list[tuple[str, str]]:
        headers: list[tuple[str, str]] = [
            (":method", request.method),
            (":scheme", request.scheme),
            (":authority", authority),
            (":path", request.target),
        ]

        for name, value in request.headers.items():
            lname = name.lower()
            if lname in H2_FORBIDDEN_HEADERS or lname in ("host", "content-length"):
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname, value))

        return headers

    def send_request(self, request: Request, authority: str) -> tuple[int, bytes]:
        stream_id = self.connection.get_next_available_stream_id()
        headers = self.build_request_headers(request, authority)
        has_body = bool(request.body)

        self.connection.send_headers(stream_id, headers, end_stream=not has_body)

        if has_body:
            self.enqueue(stream_id, request.body, end_stream=True)
            self.pump(stream_id)

        return stream_id, self.connection.data_to_send()

    def send_connect_websocket(self, request: Request, authority: str, subprotocols: list[str] | None = None, extensions: str | None = None) -> tuple[int, bytes]:
        stream_id = self.connection.get_next_available_stream_id()

        headers: list[tuple[str, str]] = [
            (":method", "CONNECT"),
            (":protocol", "websocket"),
            (":scheme", request.scheme),
            (":authority", authority),
            (":path", request.target),
            ("sec-websocket-version", "13"),
        ]
        if subprotocols:
            headers.append(("sec-websocket-protocol", ", ".join(subprotocols)))
        if extensions:
            headers.append(("sec-websocket-extensions", extensions))

        for name, value in request.headers.items():
            lname = name.lower()
            if lname in H2_FORBIDDEN_HEADERS or lname in ("host", "content-length") or lname.startswith("sec-websocket"):
                continue
            if any(c in lname for c in "\r\n\x00") or any(c in value for c in "\r\n\x00"):
                continue
            headers.append((lname, value))

        self.connection.send_headers(stream_id, headers, end_stream=False)

        queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.websocket_streams[stream_id] = queue

        return stream_id, self.connection.data_to_send()

    def send_body_chunk(self, stream_id: int, chunk: bytes, end_stream: bool) -> bytes:
        self.enqueue(stream_id, chunk, end_stream)
        self.pump(stream_id)
        return self.connection.data_to_send()

    def receive_response(self, data: bytes) -> tuple[bytes, list[tuple], bool]:
        closed = False
        events = self.connection.receive_data(data)
        out_events: list[tuple] = []

        for event in events:
            if isinstance(event, h2.events.ResponseReceived):
                status = 0
                headers = Headers({})
                for name, value in event.headers:
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

            elif isinstance(event, h2.events.DataReceived):
                if event.stream_id in self.websocket_streams:
                    if event.data:
                        self.websocket_streams[event.stream_id].put_nowait(event.data)

                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    if event.stream_ended:
                        self.websocket_streams[event.stream_id].put_nowait(None)
                        del self.websocket_streams[event.stream_id]

                else:
                    if event.data:
                        out_events.append(("data", event.stream_id, event.data))

                    self.connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)

                    if event.stream_ended:
                        out_events.append(("end", event.stream_id))

            elif isinstance(event, h2.events.StreamEnded):
                if event.stream_id in self.websocket_streams:
                    self.websocket_streams[event.stream_id].put_nowait(None)
                    del self.websocket_streams[event.stream_id]
                else:
                    out_events.append(("end", event.stream_id))

            elif isinstance(event, h2.events.StreamReset):
                if event.stream_id in self.websocket_streams:
                    self.websocket_streams[event.stream_id].put_nowait(None)
                    del self.websocket_streams[event.stream_id]
                else:
                    out_events.append(("reset", event.stream_id))

                self.discard_send(event.stream_id)

            elif isinstance(event, h2.events.RemoteSettingsChanged):
                out_events.append(("settings", 0))

            elif isinstance(event, h2.events.WindowUpdated):
                if event.stream_id == 0:
                    for sid in list(self.send_buffers.keys()):
                        self.pump(sid)
                else:
                    self.pump(event.stream_id)

            elif isinstance(event, h2.events.ConnectionTerminated):
                for queue in self.websocket_streams.values():
                    queue.put_nowait(None)

                self.websocket_streams.clear()
                self.send_buffers.clear()
                self.send_ended.clear()

                closed = True
                out_events.append(("close", 0))

        for sid in list(self.send_buffers.keys()):
            self.pump(sid)

        self.flow_control_event.set()

        return self.connection.data_to_send(), out_events, closed
