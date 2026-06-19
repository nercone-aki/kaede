"""
End-to-end WebSocket over HTTP/3 (RFC 9220 extended CONNECT) via the loopback
harness. Resolves the prior inconsistency where the server advertised
SETTINGS_ENABLE_CONNECT_PROTOCOL=1 but rejected extended CONNECT.
"""
from __future__ import annotations

import pytest

from kaede.api.models import Callback

class EchoWebSocket(Callback):
    async def on_websocket(self, request, ws):
        while True:
            message = await ws.receive()
            if message is None:
                break
            await ws.send(message)

class SubprotocolWebSocket(Callback):
    def __init__(self):
        super().__init__()
        self.websocket_subprotocols = ["chat"]

    async def on_websocket(self, request, ws):
        await ws.send(b"sub=" + (ws.subprotocol or "none").encode())

class TestWebSocketOverH3:
    async def test_echo_text(self, h3_loopback):
        lb = h3_loopback(EchoWebSocket())
        await lb.handshake()
        ws = await lb.websocket("/chat")
        await lb.drive(ws.send("hello h3 ws"))
        echo = await lb.drive(ws.receive())
        assert echo == b"hello h3 ws"

    async def test_echo_binary(self, h3_loopback):
        lb = h3_loopback(EchoWebSocket())
        await lb.handshake()
        ws = await lb.websocket("/chat")
        await lb.drive(ws.send(b"\x00\x01\x02binary"))
        echo = await lb.drive(ws.receive())
        assert echo == b"\x00\x01\x02binary"

    async def test_multiple_messages(self, h3_loopback):
        lb = h3_loopback(EchoWebSocket())
        await lb.handshake()
        ws = await lb.websocket("/chat")
        for i in range(5):
            payload = f"msg-{i}".encode()
            await lb.drive(ws.send(payload))
            assert await lb.drive(ws.receive()) == payload

    async def test_subprotocol_negotiated(self, h3_loopback):
        lb = h3_loopback(SubprotocolWebSocket())
        await lb.handshake()
        ws = await lb.websocket("/chat", subprotocols=["chat"])
        assert ws.subprotocol == "chat"
        assert await lb.drive(ws.receive()) == b"sub=chat"

    async def test_subprotocol_not_selected_when_unsupported(self, h3_loopback):
        # server offers no subprotocols; the client's offer must not be echoed back.
        lb = h3_loopback(EchoWebSocket())
        await lb.handshake()
        ws = await lb.websocket("/chat", subprotocols=["chat"])
        assert ws.subprotocol is None

    async def test_graceful_close(self, h3_loopback):
        lb = h3_loopback(EchoWebSocket())
        await lb.handshake()
        ws = await lb.websocket("/chat")
        await lb.drive(ws.send(b"bye"))
        assert await lb.drive(ws.receive()) == b"bye"
        await lb.drive(ws.close(1000))
        # after a clean close the stream ends and receive yields None
        assert await lb.drive(ws.receive()) is None

    async def test_rejected_without_connect_protocol_setting(self, h3_loopback):
        # RFC 9220 §3: the client must not use Extended CONNECT unless the server
        # advertised SETTINGS_ENABLE_CONNECT_PROTOCOL.
        lb = h3_loopback(EchoWebSocket())
        await lb.handshake()
        lb.client_h3.peer_enable_connect = False

        with pytest.raises(ConnectionError):
            await lb.websocket("/chat")
