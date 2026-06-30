from enum import Enum
from typing import Optional
from dataclasses import dataclass, field

from ..tls import TLSServerConfig
from .models import HTTPVersion

class HTTPServerRole(Enum):
    ORIGIN = "Origin"
    PROXY = "Proxy"
    GATEWAY = "Gateway"
    TUNNEL = "Tunnel"

@dataclass
class HTTPServerConfig:
    versions: list[HTTPVersion] = ["HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0"]

    tls: TLSServerConfig = field(default_factory=lambda: TLSServerConfig())

class HTTPServer:
    def __init__(self, config: Optional[HTTPServerConfig] = None, role: HTTPServerRole = HTTPServerRole.ORIGIN):
        self.role = role
        self.config = config or HTTPServerConfig()
