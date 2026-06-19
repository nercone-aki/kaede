from .models import Headers

FORBIDDEN_TRAILERS = frozenset({"transfer-encoding", "content-length", "content-encoding", "content-type", "content-range", "trailer", "host", "cache-control", "expect", "max-forwards", "pragma", "range", "te", "authorization", "set-cookie", "www-authenticate", "proxy-authenticate", "proxy-authorization", "age", "expires", "date", "location", "retry-after", "vary", "warning"})

def is_forbidden_trailer(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(":") or lowered in FORBIDDEN_TRAILERS

def build_trailers(pairs) -> Headers | None:
    if pairs is None:
        return None

    if isinstance(pairs, Headers):
        pairs = pairs.items()

    out = Headers({})
    for name, value in pairs:
        if is_forbidden_trailer(name):
            continue
        out.append(name, value)

    return out if out.headers else None
