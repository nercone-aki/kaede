"""
Content-Type / media-type parser conformance tests.
RFC 9110 §8.3 (Content-Type) and §5.6.6 (parameters).
Validates against the RFC specification, not current Kaede behavior.
"""
from __future__ import annotations

from kaede.http.headers import ContentType

# RFC 9110 §8.3.1: media-type = type "/" subtype parameters

class TestBasicParsing:
    def test_simple(self):
        ct = ContentType.parse("text/html")
        assert ct is not None
        assert ct.type == "text"
        assert ct.subtype == "html"
        assert ct.essence == "text/html"
        assert ct.parameters == {}

    def test_with_charset(self):
        ct = ContentType.parse("text/html; charset=utf-8")
        assert ct is not None
        assert ct.essence == "text/html"
        assert ct.charset == "utf-8"

    def test_multiple_parameters(self):
        ct = ContentType.parse("multipart/form-data; boundary=----abc; charset=utf-8")
        assert ct is not None
        assert ct.essence == "multipart/form-data"
        assert ct.boundary == "----abc"
        assert ct.charset == "utf-8"


class TestCaseInsensitivity:
    """RFC 9110 §8.3.1: type, subtype and parameter names are case-insensitive."""

    def test_type_subtype_lowercased(self):
        ct = ContentType.parse("TEXT/HTML")
        assert ct is not None
        assert ct.type == "text"
        assert ct.subtype == "html"
        assert ct.essence == "text/html"

    def test_parameter_name_lowercased(self):
        ct = ContentType.parse("text/html; CharSet=utf-8")
        assert ct is not None
        assert ct.charset == "utf-8"

    def test_parameter_value_case_preserved(self):
        # RFC 9110 §5.6.6: parameter values may be case-sensitive (charset is an exception, but
        # the parser must not mangle the value it returns).
        ct = ContentType.parse('text/html; charset="UTF-8"')
        assert ct is not None
        assert ct.charset == "UTF-8"


class TestQuotedStrings:
    """RFC 9110 §5.6.4: parameter values may be quoted-strings with escapes."""

    def test_quoted_value(self):
        ct = ContentType.parse('text/plain; charset="us-ascii"')
        assert ct is not None
        assert ct.charset == "us-ascii"

    def test_quoted_value_with_semicolon(self):
        ct = ContentType.parse('application/x; note="a;b"')
        assert ct is not None
        assert ct.essence == "application/x"
        assert ct.parameters["note"] == "a;b"

    def test_quoted_pair_escape(self):
        ct = ContentType.parse(r'application/x; note="a\"b"')
        assert ct is not None
        assert ct.parameters["note"] == 'a"b'


class TestMalformed:
    def test_empty(self):
        assert ContentType.parse("") is None

    def test_no_slash(self):
        assert ContentType.parse("texthtml") is None

    def test_missing_subtype(self):
        assert ContentType.parse("text/") is None

    def test_missing_type(self):
        assert ContentType.parse("/html") is None

    def test_invalid_token_in_type(self):
        # space is not a valid token character (RFC 9110 §5.6.2)
        assert ContentType.parse("te xt/html") is None


class TestBuild:
    def test_build_simple(self):
        assert ContentType.build("text", "html") == "text/html"

    def test_build_with_token_param(self):
        assert ContentType.build("text", "html", {"charset": "utf-8"}) == "text/html; charset=utf-8"

    def test_build_quotes_non_token(self):
        # a value containing a separator must be quoted (RFC 9110 §5.6.6)
        out = ContentType.build("application", "x", {"note": "a;b"})
        assert out == 'application/x; note="a;b"'

    def test_roundtrip(self):
        ct = ContentType.parse(ContentType.build("text", "plain", {"charset": "utf-8"}))
        assert ct is not None
        assert ct.essence == "text/plain"
        assert ct.charset == "utf-8"
