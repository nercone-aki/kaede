"""
Authentication header parser/builder conformance tests.
RFC 7235 (Authentication framework), RFC 7617 (Basic), RFC 6750 (Bearer).
Validates against the RFC specification, not current Kaede behavior.
"""
from __future__ import annotations

import base64

from kaede.http.headers import Authorization, WWWAuthenticate

# RFC 7235 §2.1: credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]

class TestParseScheme:
    def test_scheme_lowercased(self):
        scheme, creds = Authorization.parse("Basic dXNlcjpwYXNz")
        assert scheme == "basic"
        assert creds == "dXNlcjpwYXNz"

    def test_empty(self):
        assert Authorization.parse("") is None


class TestBasic:
    """RFC 7617 §2: Basic = base64(user-id ":" password)."""

    def test_parse(self):
        token = base64.b64encode(b"Aladdin:open sesame").decode()
        assert Authorization.parse_basic(f"Basic {token}") == ("Aladdin", "open sesame")

    def test_parse_rfc7617_example(self):
        # RFC 7617 §2 example: "Aladdin:open sesame" -> QWxhZGRpbjpvcGVuIHNlc2FtZQ==
        assert Authorization.parse_basic("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==") == ("Aladdin", "open sesame")

    def test_password_may_contain_colon(self):
        token = base64.b64encode(b"user:pa:ss").decode()
        assert Authorization.parse_basic(f"Basic {token}") == ("user", "pa:ss")

    def test_utf8_credentials(self):
        # RFC 7617 §2.1: UTF-8 is a valid charset for credentials.
        token = base64.b64encode("tëst:pä".encode("utf-8")).decode()
        assert Authorization.parse_basic(f"Basic {token}") == ("tëst", "pä")

    def test_missing_colon_invalid(self):
        token = base64.b64encode(b"nocolon").decode()
        assert Authorization.parse_basic(f"Basic {token}") is None

    def test_wrong_scheme(self):
        token = base64.b64encode(b"user:pass").decode()
        assert Authorization.parse_basic(f"Bearer {token}") is None

    def test_invalid_base64(self):
        assert Authorization.parse_basic("Basic !!!notbase64") is None

    def test_build(self):
        header = Authorization.basic("Aladdin", "open sesame")
        assert header == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="

    def test_build_rejects_colon_in_username(self):
        # RFC 7617 §2: a user-id containing a colon cannot be encoded unambiguously.
        try:
            Authorization.basic("a:b", "pw")
            assert False, "expected ValueError"
        except ValueError:
            pass

    def test_build_parse_roundtrip(self):
        assert Authorization.parse_basic(Authorization.basic("user", "p@ss")) == ("user", "p@ss")


class TestBearer:
    """RFC 6750 §2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="."""

    def test_parse(self):
        assert Authorization.parse_bearer("Bearer mF_9.B5f-4.1JqM") == "mF_9.B5f-4.1JqM"

    def test_wrong_scheme(self):
        assert Authorization.parse_bearer("Basic mF_9.B5f-4.1JqM") is None

    def test_invalid_char(self):
        # space is not allowed in b64token
        assert Authorization.parse_bearer("Bearer abc def") is None

    def test_empty_token(self):
        assert Authorization.parse_bearer("Bearer ") is None

    def test_build(self):
        assert Authorization.bearer("mF_9.B5f-4.1JqM") == "Bearer mF_9.B5f-4.1JqM"

    def test_build_rejects_invalid_token(self):
        try:
            Authorization.bearer("not a token")
            assert False, "expected ValueError"
        except ValueError:
            pass


class TestWWWAuthenticate:
    """RFC 7235 §4.1 / RFC 7617 §2: challenge = auth-scheme [ ... auth-param ]; realm is a quoted-string."""

    def test_basic_realm(self):
        assert WWWAuthenticate.build("Basic", realm="WallyWorld") == 'Basic realm="WallyWorld"'

    def test_bearer_with_error(self):
        out = WWWAuthenticate.build("Bearer", realm="api", error="invalid_token")
        assert out.startswith("Bearer ")
        assert 'realm="api"' in out
        assert "error=invalid_token" in out

    def test_scheme_only(self):
        assert WWWAuthenticate.build("Negotiate") == "Negotiate"

    def test_realm_always_quoted(self):
        # realm is defined as a quoted-string even when the value looks like a token.
        assert WWWAuthenticate.build("Basic", realm="x") == 'Basic realm="x"'
