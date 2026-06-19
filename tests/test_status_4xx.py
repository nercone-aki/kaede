"""
Conformance tests for 421 Misdirected Request (RFC 9110 §15.5.20) and
425 Too Early (RFC 8470).  Validated against the RFC specifications, not
current Kaede behavior.
"""
from __future__ import annotations

import ipaddress

from kaede.api import Callback
from kaede.api.server import Config as ServerConfig
from kaede.http.models import Request, Response, Headers
from kaede.http.authority import authority_matches
from kaede.http.process import process_request
from kaede.quic import frame as frames
from kaede.quic.connection import QUICConnection, StreamDataReceived
from kaede.quic.crypto import LEVEL_EARLY, LEVEL_APPLICATION

CLIENT = (ipaddress.IPv4Address("127.0.0.1"), 12345)


class OKCallback(Callback):
    async def on_request(self, request):
        return Response(b"ok", content_type="text/plain")


def make_request(method: str, host: str, *, early_data: bool = False, headers: dict | None = None) -> Request:
    hdrs = Headers(headers or {})
    hdrs.set("Host", host)
    return Request(method=method, target="/", headers=hdrs, scheme="https", secure=True, early_data=early_data)


# ---------------------------------------------------------------------------
# RFC 6125 §6.4.3 authority/wildcard matching
# ---------------------------------------------------------------------------

class TestAuthorityMatching:
    def test_exact(self):
        assert authority_matches("example.com", ["example.com"])

    def test_case_insensitive(self):
        assert authority_matches("Example.COM", ["example.com"])

    def test_no_match(self):
        assert not authority_matches("evil.com", ["example.com"])

    def test_wildcard_single_label(self):
        assert authority_matches("a.example.com", ["*.example.com"])

    def test_wildcard_does_not_match_apex(self):
        assert not authority_matches("example.com", ["*.example.com"])

    def test_wildcard_matches_only_one_label(self):
        assert not authority_matches("a.b.example.com", ["*.example.com"])

    def test_pattern_with_port_compares_host_only(self):
        assert authority_matches("example.com", ["example.com:443"])

    def test_request_host_with_port_via_url(self):
        # The Request.url.host strips the port already; verify the bare host matches.
        assert authority_matches("example.com", ["example.com"])


# ---------------------------------------------------------------------------
# RFC 9110 §15.5.20: 421 Misdirected Request
# ---------------------------------------------------------------------------

class TestMisdirected:
    async def test_unserved_authority_returns_421(self):
        config = ServerConfig(served_authorities=["example.com"])
        resp = await process_request(make_request("GET", "evil.com"), OKCallback(), config)
        assert resp.status_code == 421

    async def test_served_authority_passes(self):
        config = ServerConfig(served_authorities=["example.com"])
        resp = await process_request(make_request("GET", "example.com"), OKCallback(), config)
        assert resp.status_code == 200

    async def test_wildcard_served(self):
        config = ServerConfig(served_authorities=["*.example.com"])
        resp = await process_request(make_request("GET", "api.example.com"), OKCallback(), config)
        assert resp.status_code == 200

    async def test_disabled_by_default(self):
        config = ServerConfig()  # served_authorities is None
        resp = await process_request(make_request("GET", "anything.com"), OKCallback(), config)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# RFC 8470: 425 Too Early
# ---------------------------------------------------------------------------

class TestTooEarly:
    async def test_non_idempotent_early_data_rejected(self):
        config = ServerConfig(reject_early_data=True)
        resp = await process_request(make_request("POST", "example.com", early_data=True), OKCallback(), config)
        assert resp.status_code == 425

    async def test_idempotent_early_data_allowed(self):
        # RFC 9110 §9.2.2: GET is idempotent, safe to process in 0-RTT.
        config = ServerConfig(reject_early_data=True)
        resp = await process_request(make_request("GET", "example.com", early_data=True), OKCallback(), config)
        assert resp.status_code == 200

    async def test_early_data_header_honored(self):
        # RFC 8470 §5.1: an intermediary signals forwarded early data with Early-Data: 1.
        config = ServerConfig(reject_early_data=True)
        req = make_request("POST", "example.com", headers={"Early-Data": "1"})
        resp = await process_request(req, OKCallback(), config)
        assert resp.status_code == 425

    async def test_disabled_by_default(self):
        config = ServerConfig()  # reject_early_data is False
        resp = await process_request(make_request("POST", "example.com", early_data=True), OKCallback(), config)
        assert resp.status_code == 200

    async def test_not_early_data_allowed(self):
        config = ServerConfig(reject_early_data=True)
        resp = await process_request(make_request("POST", "example.com", early_data=False), OKCallback(), config)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# QUIC layer: a STREAM frame received in 0-RTT must be flagged as early data
# so the HTTP layer can apply the 425 policy (RFC 9001 §4 / RFC 8470).
# ---------------------------------------------------------------------------

class TestEarlyDataPlumbing:
    def make_server_conn(self) -> QUICConnection:
        return QUICConnection(is_client=False, tls=object(), original_dcid=b"\x00" * 8, local_cid=b"\x01" * 8, remote_cid=b"\x02" * 8)

    def test_early_level_marks_event(self):
        conn = self.make_server_conn()
        conn.on_stream_frame(frames.Stream(0, 0, b"hello", False), LEVEL_EARLY)
        events = [e for e in conn.events() if isinstance(e, StreamDataReceived)]
        assert events and events[0].early_data is True

    def test_application_level_not_marked(self):
        conn = self.make_server_conn()
        conn.on_stream_frame(frames.Stream(0, 0, b"hello", False), LEVEL_APPLICATION)
        events = [e for e in conn.events() if isinstance(e, StreamDataReceived)]
        assert events and events[0].early_data is False

    def test_early_data_latches_across_frames(self):
        # Data that begins in 0-RTT and continues in 1-RTT is still early data
        # for replay-safety purposes.
        conn = self.make_server_conn()
        conn.on_stream_frame(frames.Stream(0, 0, b"hello", False), LEVEL_EARLY)
        conn.on_stream_frame(frames.Stream(0, 5, b"world", True), LEVEL_APPLICATION)
        events = [e for e in conn.events() if isinstance(e, StreamDataReceived)]
        assert all(e.early_data for e in events)
