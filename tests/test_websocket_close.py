"""
WebSocket Close frame conformance (RFC 6455 §5.5.1, §7.4, §8.1).
"""
from __future__ import annotations

import struct

from kaede.websocket import WebSocket, Frame, Opcode, parse_frames

class CaptureTransport:
    def __init__(self):
        self.written = bytearray()
        self.closed = False

    def write(self, data):
        self.written.extend(data)

    def close(self):
        self.closed = True

def make_ws() -> WebSocket:
    return WebSocket(CaptureTransport(), require_masking=False, mask_frames=False)

def feed_close(ws: WebSocket, payload: bytes):
    ws.feed_frame(Frame(True, False, False, Opcode.CLOSE, payload, False))

def echoed_close_code(ws: WebSocket) -> int | None:
    frames = parse_frames(bytearray(ws.transport.written))
    closes = [f for f in frames if f.opcode == Opcode.CLOSE]
    if not closes or len(closes[0].payload) < 2:
        return None
    return struct.unpack(">H", closes[0].payload[:2])[0]

class TestCloseReasonUtf8:
    def test_invalid_utf8_reason_yields_1007(self):
        ws = make_ws()
        feed_close(ws, struct.pack(">H", 1000) + b"\xff\xfe")
        assert echoed_close_code(ws) == 1007

    def test_valid_reason_echoes_code(self):
        ws = make_ws()
        feed_close(ws, struct.pack(">H", 1000) + "bye".encode())
        assert echoed_close_code(ws) == 1000

class TestCloseCodeValidation:
    def test_valid_code_echoed(self):
        ws = make_ws()
        feed_close(ws, struct.pack(">H", 1001))
        assert echoed_close_code(ws) == 1001

    def test_one_byte_payload_is_protocol_error(self):
        ws = make_ws()
        feed_close(ws, b"\x03")
        assert echoed_close_code(ws) == 1002

    def test_empty_close_echoes_empty(self):
        ws = make_ws()
        feed_close(ws, b"")
        # No status code echoed for a bodyless close.
        assert echoed_close_code(ws) is None
