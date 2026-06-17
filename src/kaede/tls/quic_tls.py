from __future__ import annotations

import os
import sys
import glob
import ctypes
import ctypes.util

from .config import Group, Cipher, TLSServerConfig, TLSClientConfig, TLSInfo, CIPHER_MAP, GROUP_MAP, VERSION_MAP

LEVEL_INITIAL = 0
LEVEL_EARLY = 1
LEVEL_HANDSHAKE = 2
LEVEL_APPLICATION = 3

DIRECTION_READ = 0
DIRECTION_WRITE = 1

FUNC_CRYPTO_SEND = 2001
FUNC_CRYPTO_RECV_RCD = 2002
FUNC_CRYPTO_RELEASE_RCD = 2003
FUNC_YIELD_SECRET = 2004
FUNC_GOT_TRANSPORTVOID_PARAMS = 2005
FUNC_ALERT = 2006

SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
SSL_CTRL_SET_MINVOID_PROTO_VERSION = 123
SSL_CTRL_SET_MAXVOID_PROTO_VERSION = 124
TLSEXT_NAMETYPE_host_name = 0
TLS1_3_VERSION = 0x0304
SSL_FILETYPEVOID_PEM = 1
SSL_VERIFY_NONE = 0
SSL_VERIFYVOID_PEER = 1
SSL_VERIFY_FAIL_IF_NOVOID_PEER_CERT = 2
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_TLSEXT_ERR_OK = 0
SSL_TLSEXT_ERR_NOACK = 3

class OSSL_DISPATCH(ctypes.Structure):
    _fields_ = [("function_id", ctypes.c_int), ("function", ctypes.c_void_p)]

VOID_P = ctypes.c_void_p

CB_CRYPTO_SEND = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, VOID_P, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t), VOID_P)
CB_CRYPTO_RECV_RCD = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.POINTER(VOID_P), ctypes.POINTER(ctypes.c_size_t), VOID_P)
CB_CRYPTO_RELEASE_RCD = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.c_size_t, VOID_P)
CB_YIELD_SECRET = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.c_uint32, ctypes.c_int, VOID_P, ctypes.c_size_t, VOID_P)
CB_GOT_TRANSPORTVOID_PARAMS = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, VOID_P, ctypes.c_size_t, VOID_P)
CB_ALERT = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.c_ubyte, VOID_P)

CB_ALPN_SELECT = ctypes.CFUNCTYPE(ctypes.c_int, VOID_P, ctypes.POINTER(VOID_P), ctypes.POINTER(ctypes.c_ubyte), VOID_P, ctypes.c_uint, VOID_P)

class QuicTLSError(Exception):
    pass

def candidate_libssl_paths() -> list[str]:
    paths: list[str] = []

    env = os.environ.get("KAEDE_LIBSSL")
    if env:
        paths.append(env)

    if sys.platform == "darwin":
        patterns = [
            "/opt/homebrew/opt/openssl@3*/lib/libssl.dylib",
            "/opt/homebrew/lib/libssl.dylib",
            "/usr/local/opt/openssl@3*/lib/libssl.dylib",
            "/usr/local/lib/libssl.dylib",
        ]

        for pattern in patterns:
            paths.extend(sorted(glob.glob(pattern), reverse=True))

    else:
        patterns = [
            "/usr/lib/*/libssl.so.3",
            "/usr/lib64/libssl.so.3",
            "/usr/lib/libssl.so.3",
            "/lib/*/libssl.so.3",
            "/usr/local/lib/libssl.so.3",
        ]

        for pattern in patterns:
            paths.extend(sorted(glob.glob(pattern), reverse=True))

        for name in ("libssl.so.3", "libssl.so"):
            paths.append(name)

    found = ctypes.util.find_library("ssl")
    if found:
        paths.append(found)

    seen: set[str] = set()
    unique: list[str] = []

    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)

    return unique

class libssl:
    _instance: "libssl | None" = None

    def __init__(self):
        self.ssl: ctypes.CDLL | None = None
        self.crypto: ctypes.CDLL | None = None
        self.path: str | None = None

        for path in candidate_libssl_paths():
            try:
                lib = ctypes.CDLL(path)
            except OSError:
                continue
            if not hasattr(lib, "SSL_set_quic_tls_cbs"):
                continue
            self.ssl = lib
            self.path = path
            break

        if self.ssl is None:
            raise QuicTLSError("could not load an OpenSSL libssl exporting SSL_set_quic_tls_cbs; OpenSSL 3.5+ is required for HTTP/3 (set KAEDE_LIBSSL to override)")

        if self.path:
            crypto_path = self.path.replace("libssl", "libcrypto")
            try:
                self.crypto = ctypes.CDLL(crypto_path)
            except OSError:
                self.crypto = None

        self.configure()

    @classmethod
    def get(cls) -> "libssl":
        if cls._instance is None:
            cls._instance = libssl()
        return cls._instance

    def configure(self):
        s = self.ssl

        s.TLS_method.restype = VOID_P
        s.TLS_method.argtypes = []
        s.SSL_CTX_new.restype = VOID_P
        s.SSL_CTX_new.argtypes = [VOID_P]
        s.SSL_CTX_free.restype = None
        s.SSL_CTX_free.argtypes = [VOID_P]
        s.SSL_CTX_ctrl.restype = ctypes.c_long
        s.SSL_CTX_ctrl.argtypes = [VOID_P, ctypes.c_int, ctypes.c_long, VOID_P]
        s.SSL_CTX_use_certificate_chain_file.restype = ctypes.c_int
        s.SSL_CTX_use_certificate_chain_file.argtypes = [VOID_P, ctypes.c_char_p]
        s.SSL_CTX_use_PrivateKey_file.restype = ctypes.c_int
        s.SSL_CTX_use_PrivateKey_file.argtypes = [VOID_P, ctypes.c_char_p, ctypes.c_int]
        s.SSL_CTX_set_alpn_protos.restype = ctypes.c_int
        s.SSL_CTX_set_alpn_protos.argtypes = [VOID_P, VOID_P, ctypes.c_uint]
        s.SSL_CTX_set_alpn_select_cb.restype = None
        s.SSL_CTX_set_alpn_select_cb.argtypes = [VOID_P, VOID_P, VOID_P]
        s.SSL_CTX_set_verify.restype = None
        s.SSL_CTX_set_verify.argtypes = [VOID_P, ctypes.c_int, VOID_P]
        s.SSL_CTX_load_verify_locations.restype = ctypes.c_int
        s.SSL_CTX_load_verify_locations.argtypes = [VOID_P, ctypes.c_char_p, ctypes.c_char_p]
        s.SSL_CTX_set_default_verify_paths.restype = ctypes.c_int
        s.SSL_CTX_set_default_verify_paths.argtypes = [VOID_P]
        if hasattr(s, "SSL_CTX_set1_groups_list"):
            s.SSL_CTX_set1_groups_list.restype = ctypes.c_int
            s.SSL_CTX_set1_groups_list.argtypes = [VOID_P, ctypes.c_char_p]
        s.SSL_CTX_set_cipher_list.restype = ctypes.c_int
        s.SSL_CTX_set_cipher_list.argtypes = [VOID_P, ctypes.c_char_p]
        if hasattr(s, "SSL_CTX_set_ciphersuites"):
            s.SSL_CTX_set_ciphersuites.restype = ctypes.c_int
            s.SSL_CTX_set_ciphersuites.argtypes = [VOID_P, ctypes.c_char_p]

        s.SSL_new.restype = VOID_P
        s.SSL_new.argtypes = [VOID_P]
        s.SSL_free.restype = None
        s.SSL_free.argtypes = [VOID_P]
        s.SSL_set_connect_state.restype = None
        s.SSL_set_connect_state.argtypes = [VOID_P]
        s.SSL_set_accept_state.restype = None
        s.SSL_set_accept_state.argtypes = [VOID_P]
        s.SSL_do_handshake.restype = ctypes.c_int
        s.SSL_do_handshake.argtypes = [VOID_P]
        s.SSL_get_error.restype = ctypes.c_int
        s.SSL_get_error.argtypes = [VOID_P, ctypes.c_int]
        s.SSL_read.restype = ctypes.c_int
        s.SSL_read.argtypes = [VOID_P, VOID_P, ctypes.c_int]
        s.SSL_ctrl.restype = ctypes.c_long
        s.SSL_ctrl.argtypes = [VOID_P, ctypes.c_int, ctypes.c_long, VOID_P]
        s.SSL_set1_host.restype = ctypes.c_int
        s.SSL_set1_host.argtypes = [VOID_P, ctypes.c_char_p]
        s.SSL_set_quic_tls_cbs.restype = ctypes.c_int
        s.SSL_set_quic_tls_cbs.argtypes = [VOID_P, VOID_P, VOID_P]
        s.SSL_set_quic_tls_transport_params.restype = ctypes.c_int
        s.SSL_set_quic_tls_transport_params.argtypes = [VOID_P, VOID_P, ctypes.c_size_t]
        s.SSL_get0_alpn_selected.restype = None
        s.SSL_get0_alpn_selected.argtypes = [VOID_P, ctypes.POINTER(VOID_P), ctypes.POINTER(ctypes.c_uint)]
        s.SSL_get_current_cipher.restype = VOID_P
        s.SSL_get_current_cipher.argtypes = [VOID_P]
        s.SSL_CIPHER_get_name.restype = ctypes.c_char_p
        s.SSL_CIPHER_get_name.argtypes = [VOID_P]
        s.SSL_get_version.restype = ctypes.c_char_p
        s.SSL_get_version.argtypes = [VOID_P]
        if hasattr(s, "SSL_get0_group_name"):
            s.SSL_get0_group_name.restype = ctypes.c_char_p
            s.SSL_get0_group_name.argtypes = [VOID_P]

        if self.crypto is not None:
            self.crypto.ERR_get_error.restype = ctypes.c_ulong
            self.crypto.ERR_get_error.argtypes = []
            self.crypto.ERR_error_string_n.restype = None
            self.crypto.ERR_error_string_n.argtypes = [ctypes.c_ulong, ctypes.c_char_p, ctypes.c_size_t]

    def errors(self) -> str:
        if self.crypto is None:
            return ""

        messages: list[str] = []

        while True:
            code = self.crypto.ERR_get_error()
            if code == 0:
                break

            buf = ctypes.create_string_buffer(256)
            self.crypto.ERR_error_string_n(code, buf, len(buf))
            messages.append(buf.value.decode("ascii", "replace"))

        return "; ".join(messages)

def alpn_wire(protocols: tuple[str, ...]) -> bytes:
    out = bytearray()
    for proto in protocols:
        encoded = proto.encode("ascii")
        out.append(len(encoded))
        out.extend(encoded)
    return bytes(out)

class QuicTLS:
    def __init__(self, ctx_ptr: int, lib: libssl, *, is_client: bool, server_name: str | None = None, verify_hostname: bool = False, transport_params: bytes = b"", keepalive=()):
        self.lib = lib
        self.ctx = ctx_ptr
        self.keepalive = list(keepalive)
        self.is_client = is_client
        self.server_name = server_name

        self.secrets: dict[tuple[int, int], bytes] = {}
        self.peer_transport_params: bytes = b""
        self.handshake_complete: bool = False
        self.alert: int | None = None

        self.read_level = LEVEL_INITIAL
        self.write_level = LEVEL_INITIAL
        self.recv: dict[int, bytearray] = {LEVEL_INITIAL: bytearray(), LEVEL_EARLY: bytearray(), LEVEL_HANDSHAKE: bytearray(), LEVEL_APPLICATION: bytearray()}
        self.outgoing: list[tuple[int, bytes]] = []
        self.inflight: ctypes.Array | None = None
        self.inflight_level: int | None = None
        self.callback_error: BaseException | None = None

        ssl = self.lib.ssl
        self.SSL = ssl.SSL_new(ctx_ptr)
        if not self.SSL:
            raise QuicTLSError(f"SSL_new failed: {self.lib.errors()}")

        self.install_callbacks()

        self.tp_buf = ctypes.create_string_buffer(transport_params, len(transport_params)) if transport_params else None
        tp_ptr = ctypes.cast(self.tp_buf, VOID_P) if self.tp_buf is not None else None
        if ssl.SSL_set_quic_tls_transport_params(self.SSL, tp_ptr, len(transport_params)) != 1:
            raise QuicTLSError(f"SSL_set_quic_tls_transport_params failed: {self.lib.errors()}")

        if is_client:
            ssl.SSL_set_connect_state(self.SSL)
            if server_name:
                self.sni = server_name.encode("idna")
                ssl.SSL_ctrl(self.SSL, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, ctypes.cast(ctypes.c_char_p(self.sni), VOID_P))
                if verify_hostname:
                    ssl.SSL_set1_host(self.SSL, self.sni)
        else:
            ssl.SSL_set_accept_state(self.SSL)

    def install_callbacks(self):
        send = CB_CRYPTO_SEND(self.on_crypto_send)
        recv = CB_CRYPTO_RECV_RCD(self.on_crypto_recv_rcd)
        release = CB_CRYPTO_RELEASE_RCD(self.on_crypto_release_rcd)
        secret = CB_YIELD_SECRET(self.on_yield_secret)
        params = CB_GOT_TRANSPORTVOID_PARAMS(self.on_got_transport_params)
        alert = CB_ALERT(self.on_alert)

        self.cb_refs = [send, recv, release, secret, params, alert]

        entries = [
            (FUNC_CRYPTO_SEND, send),
            (FUNC_CRYPTO_RECV_RCD, recv),
            (FUNC_CRYPTO_RELEASE_RCD, release),
            (FUNC_YIELD_SECRET, secret),
            (FUNC_GOT_TRANSPORTVOID_PARAMS, params),
            (FUNC_ALERT, alert),
            (0, None),
        ]

        self.dispatch = (OSSL_DISPATCH * len(entries))()
        for i, (fid, fn) in enumerate(entries):
            self.dispatch[i].function_id = fid
            self.dispatch[i].function = ctypes.cast(fn, VOID_P) if fn is not None else None

        if self.lib.ssl.SSL_set_quic_tls_cbs(self.SSL, ctypes.cast(self.dispatch, VOID_P), None) != 1:
            raise QuicTLSError(f"SSL_set_quic_tls_cbs failed: {self.lib.errors()}")

    def on_crypto_send(self, ssl_p, buf, buf_len, consumed_p, arg):
        try:
            data = ctypes.string_at(buf, buf_len) if buf_len else b""
            if data:
                self.outgoing.append((self.write_level, data))
            consumed_p[0] = buf_len
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_crypto_recv_rcd(self, ssl_p, buf_pp, bytes_read_p, arg):
        try:
            pending = self.recv[self.read_level]
            if not pending:
                bytes_read_p[0] = 0
                return 1
            self.inflight = (ctypes.c_char * len(pending)).from_buffer_copy(bytes(pending))
            self.inflight_level = self.read_level
            buf_pp[0] = ctypes.cast(self.inflight, VOID_P)
            bytes_read_p[0] = len(pending)
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_crypto_release_rcd(self, ssl_p, bytes_read, arg):
        try:
            if self.inflight_level is not None:
                del self.recv[self.inflight_level][:bytes_read]
            self.inflight = None
            self.inflight_level = None
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_yield_secret(self, ssl_p, prot_level, direction, secret, secret_len, arg):
        try:
            self.secrets[(int(prot_level), int(direction))] = ctypes.string_at(secret, secret_len) if secret_len else b""
            if direction == DIRECTION_READ:
                self.read_level = int(prot_level)
            else:
                self.write_level = int(prot_level)
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_got_transport_params(self, ssl_p, params, params_len, arg):
        try:
            self.peer_transport_params = ctypes.string_at(params, params_len) if params_len else b""
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def on_alert(self, ssl_p, alert_code, arg):
        try:
            self.alert = int(alert_code)
            return 1
        except BaseException as exc:
            self.callback_error = exc
            return 0

    def provide_crypto(self, level: int, data: bytes):
        if data:
            self.recv[level].extend(data)

    def advance(self) -> list[tuple[int, bytes]]:
        ssl = self.lib.ssl
        ret = ssl.SSL_do_handshake(self.SSL)
        self.check_callback_error()

        if ret == 1:
            self.handshake_complete = True
            self.pump_post_handshake()
        else:
            err = ssl.SSL_get_error(self.SSL, ret)
            if err not in (SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE):
                raise QuicTLSError(f"TLS handshake failed (SSL_get_error={err}, alert={self.alert}): {self.lib.errors()}")

        out = self.outgoing
        self.outgoing = []
        return out

    def pump_post_handshake(self):
        ssl = self.lib.ssl
        buf = ctypes.create_string_buffer(1)
        for _ in range(8):
            ret = ssl.SSL_read(self.SSL, ctypes.cast(buf, VOID_P), 0)
            self.check_callback_error()
            if ret > 0:
                continue
            break

    def check_callback_error(self):
        if self.callback_error is not None:
            exc = self.callback_error
            self.callback_error = None
            raise QuicTLSError(f"QUIC-TLS callback raised: {exc!r}")

    def read_secret(self, level: int) -> bytes | None:
        return self.secrets.get((level, DIRECTION_READ))

    def write_secret(self, level: int) -> bytes | None:
        return self.secrets.get((level, DIRECTION_WRITE))

    def alpn(self) -> str | None:
        data = VOID_P()
        length = ctypes.c_uint()
        self.lib.ssl.SSL_get0_alpn_selected(self.SSL, ctypes.byref(data), ctypes.byref(length))
        if not data.value or not length.value:
            return None
        return ctypes.string_at(data, length.value).decode("ascii", "replace")

    def cipher_name(self) -> str | None:
        cipher = self.lib.ssl.SSL_get_current_cipher(self.SSL)
        if not cipher:
            return None
        name = self.lib.ssl.SSL_CIPHER_get_name(cipher)
        return name.decode("ascii", "replace") if name else None

    def group_name(self) -> str | None:
        if not hasattr(self.lib.ssl, "SSL_get0_group_name"):
            return None
        name = self.lib.ssl.SSL_get0_group_name(self.SSL)
        return name.decode("ascii", "replace") if name else None

    def info(self) -> TLSInfo:
        version_raw = self.lib.ssl.SSL_get_version(self.SSL)
        version = VERSION_MAP.get(version_raw.decode("ascii", "replace") if version_raw else "")

        cipher_name = self.cipher_name()
        cipher = CIPHER_MAP.get(cipher_name) if cipher_name else None

        group_name = self.group_name()
        group = GROUP_MAP.get(group_name) if group_name else None

        return TLSInfo(version=version, cipher=cipher, group=group)

    def free(self):
        if getattr(self, "SSL", None):
            self.lib.ssl.SSL_free(self.SSL)
            self.SSL = None
        if getattr(self, "ctx", None):
            self.lib.ssl.SSL_CTX_free(self.ctx)
            self.ctx = None

    def __del__(self):
        try:
            self.free()
        except Exception:
            pass

    @staticmethod
    def build_ctx(lib: libssl, *, is_client: bool, alpn: tuple[str, ...], groups: list[Group], ciphers: list[Cipher]) -> tuple[int, list]:
        ssl = lib.ssl
        ctx = ssl.SSL_CTX_new(ssl.TLS_method())
        if not ctx:
            raise QuicTLSError(f"SSL_CTX_new failed: {lib.errors()}")

        ssl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MINVOID_PROTO_VERSION, TLS1_3_VERSION, None)
        ssl.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAXVOID_PROTO_VERSION, TLS1_3_VERSION, None)

        keepalive: list = []

        if alpn:
            wire = alpn_wire(alpn)
            buf = ctypes.create_string_buffer(wire, len(wire))
            keepalive.append(buf)
            if is_client:
                if ssl.SSL_CTX_set_alpn_protos(ctx, ctypes.cast(buf, VOID_P), len(wire)) != 0:
                    raise QuicTLSError("SSL_CTX_set_alpn_protos failed")
            else:
                offered = set(alpn)

                def select(ssl_p, out_pp, outlen_p, in_p, in_len, arg, _offered=offered):
                    try:
                        data = ctypes.string_at(in_p, in_len)
                        i = 0
                        while i < len(data):
                            length = data[i]
                            proto = data[i + 1:i + 1 + length]
                            if proto.decode("ascii", "replace") in _offered:
                                out_pp[0] = ctypes.cast(ctypes.c_void_p(in_p + i + 1), VOID_P)
                                outlen_p[0] = length
                                return SSL_TLSEXT_ERR_OK
                            i += 1 + length
                        return SSL_TLSEXT_ERR_NOACK
                    except BaseException:
                        return SSL_TLSEXT_ERR_NOACK

                cb = CB_ALPN_SELECT(select)
                keepalive.append(cb)
                ssl.SSL_CTX_set_alpn_select_cb(ctx, ctypes.cast(cb, VOID_P), None)

        if groups and hasattr(ssl, "SSL_CTX_set1_groups_list"):
            spec = ":".join(g.value for g in groups).encode("ascii")
            if ssl.SSL_CTX_set1_groups_list(ctx, spec) != 1:
                ssl.SSL_CTX_free(ctx)
                raise QuicTLSError(f"SSL_CTX_set1_groups_list failed: {lib.errors()}")

        tls13 = [c for c in ciphers if c.value.startswith("TLS_")]
        tls12 = [c for c in ciphers if not c.value.startswith("TLS_")]
        if tls13 and hasattr(ssl, "SSL_CTX_set_ciphersuites"):
            spec = ":".join(c.value for c in tls13).encode("ascii")
            ssl.SSL_CTX_set_ciphersuites(ctx, spec)
        if tls12:
            spec = ":".join(c.value for c in tls12).encode("ascii")
            ssl.SSL_CTX_set_cipher_list(ctx, spec)

        return ctx, keepalive

    @classmethod
    def for_server(cls, config: TLSServerConfig, *, alpn: tuple[str, ...] = ("h3",), transport_params: bytes = b"") -> "QuicTLS":
        lib = libssl.get()
        ssl = lib.ssl
        ctx, keepalive = cls.build_ctx(lib, is_client=False, alpn=alpn, groups=config.groups, ciphers=config.ciphers)

        if config.certfile and config.keyfile:
            if ssl.SSL_CTX_use_certificate_chain_file(ctx, config.certfile.encode()) != 1:
                ssl.SSL_CTX_free(ctx)
                raise QuicTLSError(f"failed to load certificate {config.certfile!r}: {lib.errors()}")
            if ssl.SSL_CTX_use_PrivateKey_file(ctx, config.keyfile.encode(), SSL_FILETYPEVOID_PEM) != 1:
                ssl.SSL_CTX_free(ctx)
                raise QuicTLSError(f"failed to load private key {config.keyfile!r}: {lib.errors()}")

        if config.cafile:
            mode = SSL_VERIFYVOID_PEER
            if config.verify_mode == 2:
                mode |= SSL_VERIFY_FAIL_IF_NOVOID_PEER_CERT
            ssl.SSL_CTX_set_verify(ctx, mode, None)
            ssl.SSL_CTX_load_verify_locations(ctx, config.cafile.encode(), None)

        return cls(ctx, lib, is_client=False, transport_params=transport_params, keepalive=keepalive)

    @classmethod
    def for_client(cls, config: TLSClientConfig, server_name: str, *, alpn: tuple[str, ...] = ("h3",), transport_params: bytes = b"") -> "QuicTLS":
        lib = libssl.get()
        ssl = lib.ssl
        ctx, keepalive = cls.build_ctx(lib, is_client=True, alpn=alpn, groups=config.groups, ciphers=config.ciphers)

        verify_hostname = False
        if config.verify:
            ssl.SSL_CTX_set_verify(ctx, SSL_VERIFYVOID_PEER, None)
            verify_hostname = config.check_hostname
            if config.cafile or config.capath:
                ssl.SSL_CTX_load_verify_locations(
                    ctx,
                    config.cafile.encode() if config.cafile else None,
                    config.capath.encode() if config.capath else None,
                )
            else:
                ssl.SSL_CTX_set_default_verify_paths(ctx)
        else:
            ssl.SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, None)

        if config.certfile and config.keyfile:
            if ssl.SSL_CTX_use_certificate_chain_file(ctx, config.certfile.encode()) != 1:
                ssl.SSL_CTX_free(ctx)
                raise QuicTLSError(f"failed to load client certificate {config.certfile!r}: {lib.errors()}")
            if ssl.SSL_CTX_use_PrivateKey_file(ctx, config.keyfile.encode(), SSL_FILETYPEVOID_PEM) != 1:
                ssl.SSL_CTX_free(ctx)
                raise QuicTLSError(f"failed to load client private key {config.keyfile!r}: {lib.errors()}")

        return cls(ctx, lib, is_client=True, server_name=server_name, verify_hostname=verify_hostname, transport_params=transport_params, keepalive=keepalive)
