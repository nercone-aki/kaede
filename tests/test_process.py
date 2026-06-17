import gzip
import zlib
import pytest
import zstandard
import brotlicffi

from kaede.models import Request, Response
from kaede.process import parse_accept_encoding, parse_range, is_compressible, compress_response, minimize_response, compress_request, decode_content_encoding, decompress_once, StreamDecompressor, decompress_stream, wrap_streaming_response, process_response, error_response

class TestParseAcceptEncoding:
    def test_empty(self):
        assert parse_accept_encoding("") == {}

    def test_single(self):
        result = parse_accept_encoding("gzip")
        assert result == {"gzip": 1.0}

    def test_multiple(self):
        result = parse_accept_encoding("gzip, br, zstd")
        assert result["gzip"] == 1.0
        assert result["br"] == 1.0
        assert result["zstd"] == 1.0

    def test_q_value(self):
        result = parse_accept_encoding("gzip;q=0.8, br;q=1.0, zstd;q=0.5")
        assert result["gzip"] == pytest.approx(0.8)
        assert result["br"] == pytest.approx(1.0)
        assert result["zstd"] == pytest.approx(0.5)

    def test_wildcard(self):
        result = parse_accept_encoding("*")
        assert result["*"] == 1.0

    def test_q_zero(self):
        result = parse_accept_encoding("gzip;q=0")
        assert result["gzip"] == 0.0

    def test_invalid_q_defaults_to_zero(self):
        result = parse_accept_encoding("gzip;q=bad")
        assert result["gzip"] == 0.0

    def test_whitespace(self):
        result = parse_accept_encoding("  gzip  ,  br  ")
        assert "gzip" in result
        assert "br" in result

class TestParseRange:
    def test_basic_range(self):
        assert parse_range("bytes=0-99", 1000) == (0, 99)

    def test_open_ended(self):
        assert parse_range("bytes=500-", 1000) == (500, 999)

    def test_suffix(self):
        assert parse_range("bytes=-200", 1000) == (800, 999)

    def test_clamp_end(self):
        assert parse_range("bytes=0-9999", 100) == (0, 99)

    def test_start_beyond_total(self):
        assert parse_range("bytes=200-300", 100) is None

    def test_start_greater_than_end(self):
        assert parse_range("bytes=50-20", 100) is None

    def test_not_bytes(self):
        assert parse_range("tokens=0-100", 1000) is None

    def test_invalid_spec(self):
        assert parse_range("bytes=abc-def", 1000) is None

    def test_suffix_zero(self):
        assert parse_range("bytes=-0", 100) is None

    def test_multiple_ranges_uses_first(self):
        result = parse_range("bytes=0-10, 20-30", 1000)
        assert result == (0, 10)

    def test_exact_range_equal_to_total(self):
        assert parse_range("bytes=0-99", 100) == (0, 99)

    def test_single_byte(self):
        assert parse_range("bytes=0-0", 100) == (0, 0)

    def test_last_byte(self):
        assert parse_range("bytes=99-99", 100) == (99, 99)

    def test_empty_string_returns_none(self):
        assert parse_range("", 100) is None

    def test_zero_total_suffix(self):
        assert parse_range("bytes=-10", 0) is None

    def test_missing_dash_returns_none(self):
        assert parse_range("bytes=100", 200) is None

    def test_start_equals_end(self):
        assert parse_range("bytes=50-50", 100) == (50, 50)

    def test_very_large_suffix(self):
        assert parse_range("bytes=-10000", 100) == (0, 99)

class TestIsCompressible:
    def test_text_html(self):
        assert is_compressible("text/html") is True

    def test_application_json(self):
        assert is_compressible("application/json") is True

    def test_svg(self):
        assert is_compressible("image/svg+xml") is True

    def test_jpeg_not_compressible(self):
        assert is_compressible("image/jpeg") is False

    def test_png_not_compressible(self):
        assert is_compressible("image/png") is False

    def test_zip_not_compressible(self):
        assert is_compressible("application/zip") is False

    def test_woff2_not_compressible(self):
        assert is_compressible("font/woff2") is False

    def test_none_content_type(self):
        assert is_compressible(None) is True

    def test_with_charset(self):
        assert is_compressible("text/html; charset=utf-8") is True

    def test_video(self):
        assert is_compressible("video/mp4") is False

    def test_application_pdf_not_compressible(self):
        assert is_compressible("application/pdf") is False

    def test_font_woff_not_compressible(self):
        assert is_compressible("font/woff") is False

    def test_audio_not_compressible(self):
        assert is_compressible("audio/mpeg") is False

    def test_application_javascript_compressible(self):
        assert is_compressible("application/javascript") is True

    def test_text_css_compressible(self):
        assert is_compressible("text/css") is True

    def test_application_xml_compressible(self):
        assert is_compressible("application/xml") is True

    def test_image_webp_not_compressible(self):
        assert is_compressible("image/webp") is False

    def test_image_gif_not_compressible(self):
        assert is_compressible("image/gif") is False

class TestCompressResponse:
    @pytest.mark.asyncio
    async def test_gzip_compression(self):
        body = b"hello world" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"gzip": 1.0}
        compressed = await compress_response(resp, encodings)
        assert compressed is not None
        assert gzip.decompress(compressed) == body

    @pytest.mark.asyncio
    async def test_zstd_preferred_over_gzip(self):
        body = b"test data" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"gzip": 0.8, "zstd": 1.0}
        await compress_response(resp, encodings)
        assert resp.headers.get("Content-Encoding") == "zstd"

    @pytest.mark.asyncio
    async def test_no_compression_if_disabled(self):
        resp = Response(body=b"hello", compression=False)
        result = await compress_response(resp, {"gzip": 1.0})
        assert result is None

    @pytest.mark.asyncio
    async def test_no_compression_if_no_encodings(self):
        resp = Response(body=b"hello")
        result = await compress_response(resp, {})
        assert result is None

    @pytest.mark.asyncio
    async def test_no_compression_if_already_encoded(self):
        resp = Response(body=b"hello")
        resp.headers.set("Content-Encoding", "gzip")
        result = await compress_response(resp, {"gzip": 1.0})
        assert result is None

    @pytest.mark.asyncio
    async def test_no_compression_for_image(self):
        resp = Response(body=b"\xff\xd8\xff", content_type="image/jpeg")
        result = await compress_response(resp, {"gzip": 1.0})
        assert result is None

    @pytest.mark.asyncio
    async def test_vary_header_added(self):
        body = b"data" * 100
        resp = Response(body=body, content_type="text/plain")
        await compress_response(resp, {"gzip": 1.0})
        assert "Accept-Encoding" in resp.headers.get("Vary", "")

    @pytest.mark.asyncio
    async def test_q_zero_encoding_skipped(self):
        body = b"data" * 100
        resp = Response(body=body, content_type="text/plain")
        result = await compress_response(resp, {"gzip": 0.0})
        assert result is None

    @pytest.mark.asyncio
    async def test_brotli_compression(self):
        body = b"brotli compressed" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"br": 1.0}
        compressed = await compress_response(resp, encodings)
        assert compressed is not None
        assert brotlicffi.decompress(compressed) == body

    @pytest.mark.asyncio
    async def test_deflate_compression(self):
        body = b"deflate compressed" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"deflate": 1.0}
        compressed = await compress_response(resp, encodings)
        assert compressed is not None

    @pytest.mark.asyncio
    async def test_wildcard_encoding_accepted(self):
        body = b"wildcard encoding" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"*": 1.0}
        compressed = await compress_response(resp, encodings)
        assert compressed is not None

    @pytest.mark.asyncio
    async def test_wildcard_with_explicit_zero_excluded(self):
        body = b"wildcard with exclusion" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"*": 1.0, "zstd": 0.0, "br": 0.0, "gzip": 0.0}
        compressed = await compress_response(resp, encodings)
        assert compressed is not None
        assert resp.headers.get("Content-Encoding") == "deflate"

    @pytest.mark.asyncio
    async def test_streaming_body_gets_wrapped(self):
        async def gen():
            yield b"chunk one"
            yield b"chunk two"
        resp = Response(body=gen(), content_type="text/plain")
        encodings = {"gzip": 1.0}
        result = await compress_response(resp, encodings)
        assert result is not None
        assert resp.headers.get("Content-Encoding") == "gzip"

    @pytest.mark.asyncio
    async def test_highest_q_wins_among_candidates(self):
        body = b"priority test" * 100
        resp = Response(body=body, content_type="text/plain")
        encodings = {"zstd": 0.5, "br": 0.9, "gzip": 0.8}
        await compress_response(resp, encodings)
        assert resp.headers.get("Content-Encoding") == "br"

    @pytest.mark.asyncio
    async def test_content_encoding_set_after_compression(self):
        body = b"encoding header test" * 50
        resp = Response(body=body, content_type="text/plain")
        await compress_response(resp, {"gzip": 1.0})
        assert resp.headers.get("Content-Encoding") == "gzip"

class TestMinimizeResponse:
    @pytest.mark.asyncio
    async def test_minimizes_html(self):
        html = b"<html>  <body>  <p>Hello</p>  </body>  </html>"
        resp = Response(body=html, content_type="text/html", minification=True)
        result = await minimize_response(resp)
        assert result is not None
        assert len(result) <= len(html)

    @pytest.mark.asyncio
    async def test_no_minification_if_disabled(self):
        html = b"<html><body><p>Hello</p></body></html>"
        resp = Response(body=html, content_type="text/html", minification=False)
        result = await minimize_response(resp)
        assert result is None

    @pytest.mark.asyncio
    async def test_no_minification_for_non_body(self):
        resp = Response(body=None, content_type="text/html", minification=True)
        result = await minimize_response(resp)
        assert result is None

    @pytest.mark.asyncio
    async def test_minimizes_css(self):
        css = b"body   {   color:   red;   margin:  0;  }"
        resp = Response(body=css, content_type="text/css", minification=True)
        result = await minimize_response(resp)
        assert result is not None

    @pytest.mark.asyncio
    async def test_minimizes_js(self):
        js = b"function foo()   {   return   1;   }"
        resp = Response(body=js, content_type="text/javascript", minification=True)
        result = await minimize_response(resp)
        assert result is not None

    @pytest.mark.asyncio
    async def test_minimizes_svg(self):
        svg = b'<svg xmlns="http://www.w3.org/2000/svg">  <!-- comment -->  <rect x="0" y="0" width="100" height="100"/>  </svg>'
        resp = Response(body=svg, content_type="image/svg+xml", minification=True)
        result = await minimize_response(resp)
        assert result is not None

    @pytest.mark.asyncio
    async def test_minimizes_application_javascript(self):
        js = b"function   foo()   {   return   1;   }"
        resp = Response(body=js, content_type="application/javascript", minification=True)
        result = await minimize_response(resp)
        assert result is not None

    @pytest.mark.asyncio
    async def test_no_minification_for_json(self):
        data = b'{"key": "value"}'
        resp = Response(body=data, content_type="application/json", minification=True)
        result = await minimize_response(resp)
        assert result is None

    @pytest.mark.asyncio
    async def test_no_minification_when_no_content_type(self):
        resp = Response(body=b"data", content_type=None, minification=True)
        result = await minimize_response(resp)
        assert result is None

    @pytest.mark.asyncio
    async def test_uses_headers_content_type_fallback(self):
        resp = Response(body=b"body   {   color:   red;   }", content_type=None, minification=True)
        resp.headers.set("Content-Type", "text/css")
        result = await minimize_response(resp)
        assert result is not None

class TestCompressRequest:
    @pytest.mark.asyncio
    async def test_gzip_compress(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        body = b"hello world" * 100
        req = Request(method="POST", target="/", body=body)
        req.headers.set("Content-Encoding", "gzip")
        result = await compress_request(req, config)
        assert result is not None
        assert gzip.decompress(result) == body

    @pytest.mark.asyncio
    async def test_no_body_returns_none(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        req = Request(method="GET", target="/")
        result = await compress_request(req, config)
        assert result is None

    @pytest.mark.asyncio
    async def test_no_encoding_header_returns_none(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        req = Request(method="POST", target="/", body=b"hello")
        result = await compress_request(req, config)
        assert result is None

class TestDecompressOnce:
    def test_identity(self):
        assert decompress_once(b"hello", "identity", None) == b"hello"

    def test_gzip(self):
        compressed = gzip.compress(b"hello world")
        assert decompress_once(compressed, "gzip", None) == b"hello world"

    def test_deflate(self):
        compressed = zlib.compress(b"hello world")
        assert decompress_once(compressed, "deflate", None) == b"hello world"

    def test_brotli(self):
        compressed = brotlicffi.compress(b"hello world")
        assert decompress_once(compressed, "br", None) == b"hello world"

    def test_zstd(self):
        compressed = zstandard.ZstdCompressor().compress(b"hello world")
        assert decompress_once(compressed, "zstd", None) == b"hello world"

    def test_unsupported_encoding(self):
        with pytest.raises(ValueError, match="unsupported Content-Encoding"):
            decompress_once(b"data", "xz", None)

    def test_max_size_exceeded_gzip(self):
        compressed = gzip.compress(b"x" * 1000)
        with pytest.raises(ValueError, match="max_body_size"):
            decompress_once(compressed, "gzip", 500)

    def test_max_size_exceeded_brotli(self):
        compressed = brotlicffi.compress(b"x" * 1000)
        with pytest.raises(ValueError, match="max_body_size"):
            decompress_once(compressed, "br", 500)

    def test_max_size_exceeded_zstd(self):
        compressed = zstandard.ZstdCompressor().compress(b"x" * 1000)
        with pytest.raises(ValueError, match="max_body_size"):
            decompress_once(compressed, "zstd", 500)

class TestStreamDecompressor:
    def test_gzip_stream(self):
        raw = b"hello world" * 10
        compressed = gzip.compress(raw)
        decompressor = StreamDecompressor("gzip")
        result = decompressor.feed(compressed) + decompressor.flush()
        assert result == raw

    def test_identity_passthrough(self):
        decompressor = StreamDecompressor("identity")
        result = decompressor.feed(b"hello")
        assert result == b"hello"

    def test_zstd_stream(self):
        raw = b"test data" * 50
        compressed = zstandard.ZstdCompressor().compress(raw)
        decompressor = StreamDecompressor("zstd")
        result = decompressor.feed(compressed)
        assert result == raw

    def test_empty_feed(self):
        decompressor = StreamDecompressor("gzip")
        assert decompressor.feed(b"") == b""

    def test_brotli_stream(self):
        raw = b"hello brotli world" * 10
        compressed = brotlicffi.compress(raw)
        decomp = StreamDecompressor("br")
        result = decomp.feed(compressed)
        assert result == raw

    def test_deflate_stream(self):
        raw = b"hello deflate" * 20
        compressed = zlib.compress(raw)
        decomp = StreamDecompressor("deflate")
        result = decomp.feed(compressed) + decomp.flush()
        assert result == raw

    def test_x_gzip_alias(self):
        raw = b"x-gzip alias test" * 10
        compressed = gzip.compress(raw)
        decomp = StreamDecompressor("x-gzip")
        result = decomp.feed(compressed) + decomp.flush()
        assert result == raw

    def test_flush_returns_empty_for_non_zlib(self):
        decomp = StreamDecompressor("br")
        assert decomp.flush() == b""

    def test_flush_returns_empty_for_identity(self):
        decomp = StreamDecompressor("identity")
        assert decomp.flush() == b""

    def test_zstd_empty_chunk(self):
        decomp = StreamDecompressor("zstd")
        assert decomp.feed(b"") == b""

    def test_identity_passthrough(self):
        decomp = StreamDecompressor("identity")
        assert decomp.feed(b"raw data") == b"raw data"
        assert decomp.feed(b"more data") == b"more data"

    def test_gzip_incremental_feed(self):
        raw = b"incremental gzip" * 50
        compressed = gzip.compress(raw)
        decomp = StreamDecompressor("gzip")
        chunk_size = 20
        result = bytearray()
        for i in range(0, len(compressed), chunk_size):
            result.extend(decomp.feed(compressed[i:i + chunk_size]))
        result.extend(decomp.flush())
        assert bytes(result) == raw

class TestDecodeContentEncoding:
    def test_single_gzip(self):
        compressed = gzip.compress(b"hello")
        assert decode_content_encoding(compressed, ["gzip"], None) == b"hello"

    def test_chained_encodings(self):
        data = b"hello world"
        gz = gzip.compress(data)
        br = brotlicffi.compress(gz)
        result = decode_content_encoding(br, ["gzip", "br"], None)
        assert result == data

    def test_empty_encodings_passthrough(self):
        data = b"plain data"
        assert decode_content_encoding(data, [], None) == data

    def test_identity_encoding_passthrough(self):
        data = b"plain data"
        assert decode_content_encoding(data, ["identity"], None) == data

    def test_single_brotli(self):
        compressed = brotlicffi.compress(b"brotli test")
        assert decode_content_encoding(compressed, ["br"], None) == b"brotli test"

    def test_single_zstd(self):
        compressed = zstandard.ZstdCompressor().compress(b"zstd test")
        assert decode_content_encoding(compressed, ["zstd"], None) == b"zstd test"

class TestDecompressStream:
    @pytest.mark.asyncio
    async def test_gzip_stream(self):
        raw = b"async gzip stream test" * 30
        compressed = gzip.compress(raw)

        async def source():
            yield compressed

        result = bytearray()
        async for chunk in decompress_stream(source(), ["gzip"], None):
            result.extend(chunk)
        assert bytes(result) == raw

    @pytest.mark.asyncio
    async def test_identity_filtered_from_chain(self):
        raw = b"identity filtered"

        async def source():
            yield raw

        result = bytearray()
        async for chunk in decompress_stream(source(), ["identity"], None):
            result.extend(chunk)
        assert bytes(result) == raw

    @pytest.mark.asyncio
    async def test_max_size_exceeded_raises(self):
        raw = b"x" * 1000
        compressed = gzip.compress(raw)

        async def source():
            yield compressed

        with pytest.raises(ValueError, match="max_body_size"):
            async for _ in decompress_stream(source(), ["gzip"], 500):
                pass

    @pytest.mark.asyncio
    async def test_chained_encodings(self):
        raw = b"chained decompression" * 20
        gz = gzip.compress(raw)
        br = brotlicffi.compress(gz)

        async def source():
            yield br

        result = bytearray()
        async for chunk in decompress_stream(source(), ["gzip", "br"], None):
            result.extend(chunk)
        assert bytes(result) == raw

    @pytest.mark.asyncio
    async def test_multiple_chunks(self):
        raw = b"multi-chunk test" * 50
        compressed = gzip.compress(raw)

        async def source():
            size = 32
            for i in range(0, len(compressed), size):
                yield compressed[i:i + size]

        result = bytearray()
        async for chunk in decompress_stream(source(), ["gzip"], None):
            result.extend(chunk)
        assert bytes(result) == raw

class TestErrorResponse:
    def _make_config(self):
        from kaede.api.server import Config as ServerConfig
        return ServerConfig()

    def test_basic_error_response(self):
        config = self._make_config()
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert resp.status_code == 500
        assert resp.body == b"Internal Server Error"

    def test_error_response_has_content_length(self):
        config = self._make_config()
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert resp.headers.get("Content-Length") == str(len(b"Internal Server Error"))

    def test_error_response_head_strips_body(self):
        config = self._make_config()
        req = Request(method="HEAD", target="/")
        resp = error_response(req, config)
        assert resp.body is None

    def test_error_response_content_type_is_plain(self):
        config = self._make_config()
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert "text/plain" in (resp.headers.get("Content-Type") or "")

    def test_error_response_compression_disabled(self):
        config = self._make_config()
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert resp.compression is False

    def test_error_response_server_header(self):
        from kaede.api.server import Config as ServerConfig
        config = ServerConfig(server_name="TestServer")
        req = Request(method="GET", target="/")
        resp = error_response(req, config)
        assert resp.headers.get("Server") == "TestServer"

class TestProcessResponse:
    @pytest.mark.asyncio
    async def test_decompresses_gzip_response(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        body = b"hello from server"
        compressed = gzip.compress(body)
        resp = Response(body=compressed, status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        result = await process_response(resp, Request(method="GET", target="/"), config)
        assert result.body == body
        assert result.headers.get("Content-Encoding") is None

    @pytest.mark.asyncio
    async def test_no_decompress_if_disabled(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig(decompress=False)
        compressed = gzip.compress(b"data")
        resp = Response(body=compressed, status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        result = await process_response(resp, Request(method="GET", target="/"), config)
        assert result.body == compressed
        assert result.headers.get("Content-Encoding") == "gzip"

    @pytest.mark.asyncio
    async def test_no_decompress_if_no_encoding_header(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        body = b"plain body"
        resp = Response(body=body, status_code=200)
        result = await process_response(resp, Request(method="GET", target="/"), config)
        assert result.body == body

    @pytest.mark.asyncio
    async def test_no_decompress_for_streaming_body(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()

        async def gen():
            yield gzip.compress(b"chunk")

        resp = Response(body=gen(), status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        result = await process_response(resp, Request(method="GET", target="/"), config)
        assert result.is_streaming

    @pytest.mark.asyncio
    async def test_content_length_updated_after_decompression(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()
        body = b"hello decompressed"
        compressed = gzip.compress(body)
        resp = Response(body=compressed, status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        resp.headers.set("Content-Length", str(len(compressed)))
        result = await process_response(resp, Request(method="GET", target="/"), config)
        assert result.headers.get("Content-Length") == str(len(body))

class TestWrapStreamingResponse:
    def test_wraps_gzip_streaming(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()

        async def gen():
            yield gzip.compress(b"stream")

        resp = Response(body=gen(), status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        result = wrap_streaming_response(resp, config)
        assert result.headers.get("Content-Encoding") is None
        assert result.is_streaming

    def test_no_wrap_if_decompress_disabled(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig(decompress=False)

        async def gen():
            yield b"data"

        resp = Response(body=gen(), status_code=200)
        resp.headers.set("Content-Encoding", "gzip")
        result = wrap_streaming_response(resp, config)
        assert result.headers.get("Content-Encoding") == "gzip"

    def test_no_wrap_if_no_encoding(self):
        from kaede.api.client import Config as ClientConfig
        config = ClientConfig()

        async def gen():
            yield b"data"

        resp = Response(body=gen(), status_code=200)
        result = wrap_streaming_response(resp, config)
        assert result is resp
