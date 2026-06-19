from __future__ import annotations

def normalize_host(host: str) -> str:
    host = host.strip().lower()

    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    return host

def authority_matches(host: str, patterns: list[str]) -> bool:
    host = normalize_host(host)
    if not host:
        return False

    for pattern in patterns:
        pattern = normalize_host(pattern)
        if not pattern:
            continue

        if ":" in pattern and not pattern.startswith("["):
            pattern = pattern.rsplit(":", 1)[0]

        if pattern == host:
            return True

        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) and host.count(".") == pattern.count("."):
                return True

    return False
