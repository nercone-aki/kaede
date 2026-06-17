from __future__ import annotations

from dataclasses import dataclass

from . import qpack
from ..quic.packet import Buffer, encode_uint_var
from ..quic import StreamDataReceived
from ..quic.stream import stream_is_bidirectional

H3_FORBIDDEN_HEADERS = ("connection", "transfer-encoding", "keep-alive", "upgrade", "proxy-connection")

FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_CANCEL_PUSH = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_GOAWAY = 0x7
FRAME_MAX_PUSH_ID = 0xD

STREAM_CONTROL = 0x00
STREAM_PUSH = 0x01
STREAM_QPACK_ENCODER = 0x02
STREAM_QPACK_DECODER = 0x03

SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x01
SETTINGS_MAX_FIELD_SECTION_SIZE = 0x06
SETTINGS_QPACK_BLOCKED_STREAMS = 0x07
SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x08

@dataclass
class H3Info:
    connection_id: bytes
    stream_id: int

@dataclass
class H3WSUpgrade:
    stream_id: int
    request: object

@dataclass
class HeadersReceived:
    stream_id: int
    headers: list[tuple[bytes, bytes]]
    stream_ended: bool = False

@dataclass
class DataReceived:
    stream_id: int
    data: bytes
    stream_ended: bool = False

def encode_frame(frame_type: int, payload: bytes) -> bytes:
    return encode_uint_var(frame_type) + encode_uint_var(len(payload)) + payload

def encode_settings() -> bytes:
    body = bytearray()

    for ident, value in ((SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0), (SETTINGS_QPACK_BLOCKED_STREAMS, 0), (SETTINGS_ENABLE_CONNECT_PROTOCOL, 1)):
        body += encode_uint_var(ident)
        body += encode_uint_var(value)

    return encode_frame(FRAME_SETTINGS, bytes(body))

class H3:
    def __init__(self, quic, is_client: bool = False, connection_id: bytes = b"", max_body_size: int = 16 * 1024 * 1024):
        self.quic = quic
        self.is_client = is_client
        self.connection_id = connection_id
        self.max_body_size = max_body_size

        self.control_stream_id: int | None = None
        self.peer_uni_types: dict[int, int] = {}
        self.uni_buffers: dict[int, bytearray] = {}
        self.request_buffers: dict[int, bytearray] = {}
        self.finished: set[int] = set()

        self.setup()

    def setup(self):
        self.control_stream_id = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(self.control_stream_id, encode_uint_var(STREAM_CONTROL) + encode_settings(), end_stream=False)

        enc = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(enc, encode_uint_var(STREAM_QPACK_ENCODER), end_stream=False)

        dec = self.quic.get_next_available_stream_id(is_bidi=False)
        self.quic.send_stream_data(dec, encode_uint_var(STREAM_QPACK_DECODER), end_stream=False)

    def open_request_stream(self) -> int:
        return self.quic.get_next_available_stream_id(is_bidi=True)

    def send_headers(self, stream_id: int, headers: list[tuple[bytes, bytes]], end_stream: bool = False):
        field_section = qpack.encode_headers(headers)
        self.quic.send_stream_data(stream_id, encode_frame(FRAME_HEADERS, field_section), end_stream=end_stream)

    def send_data(self, stream_id: int, data: bytes, end_stream: bool = False):
        self.quic.send_stream_data(stream_id, encode_frame(FRAME_DATA, data), end_stream=end_stream)

    def feed(self, events: list) -> list:
        out: list = []

        for event in events:
            if not isinstance(event, StreamDataReceived):
                continue

            sid = event.stream_id

            if stream_is_bidirectional(sid):
                self.feed_request_stream(sid, event.data, event.end_stream, out)

            else:
                self.feed_uni_stream(sid, event.data, event.end_stream)

        return out

    def feed_uni_stream(self, sid: int, data: bytes, end_stream: bool):
        buf = self.uni_buffers.setdefault(sid, bytearray())
        buf.extend(data)

        if sid not in self.peer_uni_types:
            reader = Buffer(bytes(buf))

            try:
                stream_type = reader.pull_uint_var()
            except Exception:
                return

            self.peer_uni_types[sid] = stream_type

            del buf[:reader.tell()]

        buf.clear()

    def feed_request_stream(self, sid: int, data: bytes, end_stream: bool, out: list):
        buf = self.request_buffers.setdefault(sid, bytearray())
        buf.extend(data)

        while True:
            reader = Buffer(bytes(buf))

            try:
                frame_type = reader.pull_uint_var()
                length = reader.pull_uint_var()
            except Exception:
                break

            header_len = reader.tell()

            if len(buf) - header_len < length:
                break

            payload = bytes(buf[header_len:header_len + length])

            del buf[:header_len + length]

            if frame_type == FRAME_HEADERS:
                try:
                    headers = qpack.decode_headers(payload)
                except qpack.QpackError:
                    return
                out.append(HeadersReceived(sid, headers, stream_ended=False))
            elif frame_type == FRAME_DATA:
                out.append(DataReceived(sid, payload, stream_ended=False))

        if end_stream and sid not in self.finished:
            self.finished.add(sid)
            out.append(DataReceived(sid, b"", stream_ended=True))
