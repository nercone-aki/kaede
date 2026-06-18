"""
QUIC Retry / address validation conformance (RFC 9000 §8.1, §17.2.5, §7.3).

The server answers the first Initial with a Retry; the client validates the
Retry integrity tag, re-sends its Initial carrying the token, and the server
validates the token before creating connection state. The handshake then
completes and the client validates original/retry source connection IDs.
"""
from __future__ import annotations

from kaede.quic.connection import (
    QUICConnection, make_retry_token, validate_retry_token,
    TP_ORIGINAL_DCID, TP_RETRY_SOURCE_CONNECTION_ID,
)
from kaede.quic.connection import StreamDataReceived

class TestToken:
    def test_round_trip(self):
        secret = b"s" * 32
        odcid = b"\x01" * 8
        token = make_retry_token(secret, odcid)
        assert validate_retry_token(secret, token) == odcid

    def test_tampered_token_rejected(self):
        secret = b"s" * 32
        token = bytearray(make_retry_token(secret, b"\x01" * 8))
        token[0] ^= 0xFF
        assert validate_retry_token(secret, bytes(token)) is None

    def test_wrong_secret_rejected(self):
        token = make_retry_token(b"a" * 32, b"\x01" * 8)
        assert validate_retry_token(b"b" * 32, token) is None

class TestRetryHandshake:
    def test_handshake_completes_after_retry(self, quic_pair_retry):
        assert quic_pair_retry.handshake()
        assert quic_pair_retry.client.handshake_confirmed
        assert quic_pair_retry.server.handshake_confirmed

    def test_client_recorded_retry_source(self, quic_pair_retry):
        quic_pair_retry.handshake()
        assert quic_pair_retry.client.retry_source_cid is not None

    def test_transport_params_consistent(self, quic_pair_retry):
        quic_pair_retry.handshake()
        client = quic_pair_retry.client
        # Server advertised the true original DCID and the Retry source CID.
        assert client.peer_transport_params.get(TP_ORIGINAL_DCID) == client.original_dcid
        assert client.peer_transport_params.get(TP_RETRY_SOURCE_CONNECTION_ID) == client.retry_source_cid

    def test_streams_work_after_retry(self, quic_pair_retry):
        quic_pair_retry.handshake()
        sid = quic_pair_retry.client.get_next_available_stream_id(is_bidi=True)
        quic_pair_retry.client.send_stream_data(sid, b"after-retry", end_stream=True)
        quic_pair_retry.pump()
        data = b"".join(e.data for e in quic_pair_retry.server.events() if isinstance(e, StreamDataReceived) and e.stream_id == sid)
        assert data == b"after-retry"

class TestRetryRejection:
    def test_server_rejects_missing_token(self, tls_cert):
        # Without a token, create_server with a retry_secret must fail.
        from kaede.quic.tls import QuicTLS
        from kaede.tls.models import TLSServerConfig, TLSClientConfig
        import ssl

        certfile, keyfile = tls_cert
        client = QUICConnection.create_client(
            lambda tp: QuicTLS.for_client(TLSClientConfig(verify=False, check_hostname=False), "localhost", transport_params=tp), "localhost",
        )
        initial = client.datagrams_to_send(0.0)
        server_cfg = TLSServerConfig(certfile=certfile, keyfile=keyfile, verify_mode=ssl.CERT_NONE)

        import pytest
        with pytest.raises(ValueError):
            QUICConnection.create_server(
                initial[0][0],
                lambda tp: QuicTLS.for_server(server_cfg, transport_params=tp),
                retry_secret=b"x" * 32,
            )
