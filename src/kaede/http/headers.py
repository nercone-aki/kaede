from __future__ import annotations

import base64
from dataclasses import dataclass, field

from ..common import unquote, split_list, split_semicolons
from ..constants import Characters

TOKEN_CHARS     = set("!#$%&'*+-.^_`|~") | Characters.DIGIT | Characters.LOWER | Characters.UPPER
TOKEN_CHARS_B64 = set("-._~+/")          | Characters.DIGIT | Characters.LOWER | Characters.UPPER

def is_token(value: str) -> bool:
    return bool(value) and all(ch in TOKEN_CHARS for ch in value)

def quote_value(value: str) -> str:
    if is_token(value):
        return value

    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'

def parse_params(segments: list[str]) -> dict[str, str]:
    params: dict[str, str] = {}

    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue

        name, eq, raw = seg.partition("=")
        name = name.strip().lower()
        if not name:
            continue

        params[name] = unquote(raw.strip()) if eq else ""

    return params

class ETag:
    @staticmethod
    def parse(value: str) -> tuple[bool, str] | None:
        value = value.strip()
        weak = False

        if value.startswith("W/"):
            weak = True
            value = value[2:]

        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return weak, value

        return None

    @staticmethod
    def strong_match(a: str, b: str) -> bool:
        pa, pb = ETag.parse(a), ETag.parse(b)
        if pa is None or pb is None:
            return False
        return (not pa[0]) and (not pb[0]) and pa[1] == pb[1]

    @staticmethod
    def weak_match(a: str, b: str) -> bool:
        pa, pb = ETag.parse(a), ETag.parse(b)
        if pa is None or pb is None:
            return False
        return pa[1] == pb[1]

class AcceptEncoding:
    @staticmethod
    def parse(value: str) -> dict[str, float]:
        out: dict[str, float] = {}

        for element in split_list(value):
            head, params = AcceptEncoding.parse_params(element)
            head = head.lower()
            if not head:
                continue

            q = 1.0
            if "q" in params:
                try:
                    q = max(0.0, min(1.0, float(params["q"])))
                except (ValueError, TypeError):
                    q = 0.0

            params.pop("q", None)
            out[head] = q

        return out

    @staticmethod
    def parse_params(value: str) -> tuple[str, dict[str, str]]:
        segments = split_semicolons(value)
        head = segments[0].strip()
        params: dict[str, str] = {}

        for seg in segments[1:]:
            seg = seg.strip()
            if not seg:
                continue

            name, eq, raw = seg.partition("=")
            name = name.strip().lower()
            if not name:
                continue

            params[name] = unquote(raw.strip()) if eq else ""

        return head, params

class ContentType:
    def __init__(self, type: str, subtype: str, parameters: dict[str, str] | None = None):
        self.type = type
        self.subtype = subtype
        self.parameters: dict[str, str] = parameters or {}

    @property
    def essence(self) -> str:
        return f"{self.type}/{self.subtype}"

    @property
    def charset(self) -> str | None:
        return self.parameters.get("charset")

    @property
    def boundary(self) -> str | None:
        return self.parameters.get("boundary")

    @staticmethod
    def parse(value: str) -> ContentType | None:
        if not value:
            return None

        segments = split_semicolons(value)
        head = segments[0].strip().lower()

        if "/" not in head:
            return None

        type, _, subtype = head.partition("/")
        type = type.strip()
        subtype = subtype.strip()

        if not is_token(type) or not is_token(subtype):
            return None

        return ContentType(type, subtype, parse_params(segments[1:]))

    @staticmethod
    def build(type: str, subtype: str, parameters: dict[str, str] | None = None) -> str:
        out = f"{type}/{subtype}"

        for name, value in (parameters or {}).items():
            out += f"; {name}={quote_value(value)}"

        return out

@dataclass
class LinkValue:
    target: str
    params: dict[str, str] = field(default_factory=dict)

    @property
    def rel(self) -> str | None:
        return self.params.get("rel")

class Link:
    @staticmethod
    def split(value: str) -> list[str]:
        parts: list[str] = []
        buf: list[str] = []
        in_quote = False
        in_angle = False
        escaped = False

        for ch in value:
            if in_quote:
                buf.append(ch)

                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_quote = False

            elif ch == '"':
                in_quote = True
                buf.append(ch)

            elif ch == "<":
                in_angle = True
                buf.append(ch)

            elif ch == ">":
                in_angle = False
                buf.append(ch)

            elif ch == "," and not in_angle:
                parts.append("".join(buf))
                buf = []

            else:
                buf.append(ch)

        parts.append("".join(buf))
        return parts

    @staticmethod
    def parse(value: str) -> list[LinkValue]:
        links: list[LinkValue] = []

        for chunk in Link.split(value):
            chunk = chunk.strip()
            if not chunk.startswith("<"):
                continue

            end = chunk.find(">")
            if end == -1:
                continue

            target = chunk[1:end].strip()
            rest = chunk[end + 1:]

            links.append(LinkValue(target, parse_params(split_semicolons(rest))))

        return links

    @staticmethod
    def build(links: list[LinkValue]) -> str:
        out: list[str] = []

        for link in links:
            built = f"<{link.target}>"

            for name, value in link.params.items():
                if value == "":
                    built += f"; {name}"
                else:
                    built += f"; {name}={quote_value(value)}"

            out.append(built)

        return ", ".join(out)

class Authorization:
    @staticmethod
    def parse(value: str) -> tuple[str, str] | None:
        value = value.strip()
        if not value:
            return None

        scheme, _, credentials = value.partition(" ")
        scheme = scheme.strip().lower()
        if not scheme:
            return None

        return scheme, credentials.strip()

    @staticmethod
    def parse_basic(value: str) -> tuple[str, str] | None:
        parsed = Authorization.parse(value)
        if parsed is None:
            return None

        scheme, credentials = parsed
        if scheme != "basic" or not credentials:
            return None

        try:
            raw = base64.b64decode(credentials, validate=True)
        except Exception:
            return None

        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            decoded = raw.decode("latin-1")

        if ":" not in decoded:
            return None

        user, _, password = decoded.partition(":")
        return user, password

    @staticmethod
    def parse_bearer(value: str) -> str | None:
        parsed = Authorization.parse(value)
        if parsed is None:
            return None

        scheme, credentials = parsed
        if scheme != "bearer" or not Authorization.is_b64token(credentials):
            return None

        return credentials

    @staticmethod
    def is_b64token(token: str) -> bool:
        if not token:
            return False

        core = token.rstrip("=")
        return bool(core) and all(ch in TOKEN_CHARS_B64 for ch in core)

    @staticmethod
    def basic(username: str, password: str) -> str:
        if ":" in username:
            raise ValueError("username must not contain a colon")

        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    @staticmethod
    def bearer(token: str) -> str:
        if not Authorization.is_b64token(token):
            raise ValueError("invalid bearer token")

        return f"Bearer {token}"

class WWWAuthenticate:
    @staticmethod
    def build(scheme: str, **params: str | None) -> str:
        parts: list[str] = []

        for name, value in params.items():
            if value is None:
                continue

            name = name.replace("_", "-")

            if name == "realm":
                escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
                parts.append(f'{name}="{escaped}"')
            else:
                parts.append(f"{name}={quote_value(str(value))}")

        if parts:
            return f"{scheme} " + ", ".join(parts)

        return scheme
