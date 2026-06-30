from typing import Literal, Optional
from dataclasses import dataclass, field

from ..url import URL
from ..tls import TLSClientConfig
from .models import HTTPVersion, HTTPHeaders, HTTPResponse
from .websocket import WSConnection

@dataclass
class HTTPClientConfig:
    versions: list[HTTPVersion] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]

    tls: TLSClientConfig = field(default_factory=lambda: TLSClientConfig())

class HTTPClient:
    def __init__(self, config: Optional[HTTPClientConfig] = None):
        self.config = config or HTTPClientConfig()

    async def request(self, method: Literal["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"], url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def get(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def head(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def post(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def put(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def delete(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def connect(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def options(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def trace(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def patch(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> HTTPResponse:
        ...

    async def websocket(self, url: str | URL, headers: Optional[HTTPHeaders | dict[str, str] | list[tuple[str, list[str]]]], cookies: Optional[dict[str, str]], timeout: Optional[float]) -> WSConnection:
        ...

    async def close(self):
        ...
