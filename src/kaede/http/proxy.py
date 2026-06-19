from __future__ import annotations

import asyncio

from .models import Request, Response, Headers

HOP_BY_HOP = frozenset({"connection", "proxy-connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization"})

def hop_by_hop_fields(headers: Headers) -> set[str]:
    fields = set(HOP_BY_HOP)
    connection = headers.get("Connection") or ""
    for token in connection.split(","):
        token = token.strip().lower()
        if token:
            fields.add(token)
    return fields

def strip_hop_by_hop(headers: Headers) -> None:
    for field in hop_by_hop_fields(headers):
        headers.remove(field)

class TunnelProtocol(asyncio.Protocol):
    def __init__(self, client_transport):
        self.client_transport = client_transport
        self.transport: asyncio.Transport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data: bytes):
        if self.client_transport is not None and not self.client_transport.is_closing():
            self.client_transport.write(data)

    def connection_lost(self, exc):
        if self.client_transport is not None and not self.client_transport.is_closing():
            self.client_transport.close()

class ReverseProxy:
    def __init__(self, upstream: str, client=None):
        self.upstream = upstream.rstrip("/")

        if client is None:
            from ..api.client import Client, Config
            self.client = Client(Config(decompress=False))
            self.owns_client = True
        else:
            self.client = client
            self.owns_client = False

    async def forward(self, request: Request, *, streaming: bool = True) -> Response:
        url = self.upstream + request.target

        headers: dict[str, str] = {}
        drop = hop_by_hop_fields(request.headers)

        for name in request.headers.headers:
            if name in drop or name == "host":
                continue

            value = request.headers.get(name)

            if isinstance(value, list):
                value = ", ".join(value)

            if value is not None:
                headers[name] = value

        client_ip = str(request.client[0])

        headers["X-Forwarded-For"] = f"{request.headers.get('X-Forwarded-For')}, {client_ip}" if request.headers.get("X-Forwarded-For") else client_ip
        headers["X-Forwarded-Proto"] = request.scheme
        headers["Forwarded"] = f"for={client_ip};proto={request.scheme}"

        if request.early_data:
            headers["Early-Data"] = "1"

        response = await self.client.handler.request(request.method, url, headers, request.body, streaming)

        strip_hop_by_hop(response.headers)
        return response

    async def close(self):
        if self.owns_client:
            await self.client.close()
