"""
Link header parser conformance tests.
RFC 8288 (Web Linking).
Validates against the RFC specification, not current Kaede behavior.
"""
from __future__ import annotations

from kaede.http.headers import Link, LinkValue

# RFC 8288 §3: link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )

class TestSingleLink:
    def test_simple(self):
        links = Link.parse('</style.css>; rel=preload')
        assert len(links) == 1
        assert links[0].target == "/style.css"
        assert links[0].rel == "preload"

    def test_quoted_rel(self):
        links = Link.parse('</style.css>; rel="preload stylesheet"')
        assert len(links) == 1
        assert links[0].params["rel"] == "preload stylesheet"

    def test_multiple_params(self):
        links = Link.parse('</a>; rel=next; type="text/html"; title="A"')
        assert len(links) == 1
        assert links[0].params["rel"] == "next"
        assert links[0].params["type"] == "text/html"
        assert links[0].params["title"] == "A"

    def test_absolute_uri(self):
        links = Link.parse('<https://example.com/>; rel="start"')
        assert len(links) == 1
        assert links[0].target == "https://example.com/"
        assert links[0].rel == "start"


class TestMultipleLinks:
    """RFC 8288 §3: Link = #link-value (comma separated list)."""

    def test_two_links(self):
        links = Link.parse('</a>; rel=prev, </b>; rel=next')
        assert len(links) == 2
        assert links[0].target == "/a"
        assert links[0].rel == "prev"
        assert links[1].target == "/b"
        assert links[1].rel == "next"

    def test_comma_inside_uri_not_a_separator(self):
        # commas inside the angle-bracketed URI-Reference must not split link-values.
        links = Link.parse('</search?q=a,b>; rel=search')
        assert len(links) == 1
        assert links[0].target == "/search?q=a,b"
        assert links[0].rel == "search"

    def test_comma_inside_quoted_param_not_a_separator(self):
        links = Link.parse('</a>; rel=next; title="a, b", </c>; rel=last')
        assert len(links) == 2
        assert links[0].params["title"] == "a, b"
        assert links[1].target == "/c"
        assert links[1].rel == "last"


class TestParameterNormalization:
    def test_param_name_lowercased(self):
        links = Link.parse('</a>; REL=next')
        assert links[0].rel == "next"


class TestMalformed:
    def test_missing_angle_brackets(self):
        # a link-value must begin with "<" (RFC 8288 §3)
        assert Link.parse("/a; rel=next") == []

    def test_unterminated_angle(self):
        assert Link.parse("</a; rel=next") == []

    def test_empty(self):
        assert Link.parse("") == []


class TestBuild:
    def test_build_simple(self):
        out = Link.build([LinkValue("/style.css", {"rel": "preload"})])
        assert out == "</style.css>; rel=preload"

    def test_build_quotes_multivalue_rel(self):
        out = Link.build([LinkValue("/a", {"rel": "preload stylesheet"})])
        assert out == '</a>; rel="preload stylesheet"'

    def test_build_multiple(self):
        out = Link.build([LinkValue("/a", {"rel": "prev"}), LinkValue("/b", {"rel": "next"})])
        assert out == "</a>; rel=prev, </b>; rel=next"

    def test_roundtrip(self):
        original = '</a>; rel=next; title="a, b"'
        links = Link.parse(original)
        rebuilt = Link.build(links)
        assert Link.parse(rebuilt) == links
