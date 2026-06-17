from __future__ import annotations

import ssl
import sys
import ctypes
import ctypes.util
from typing import TYPE_CHECKING

from .config import Group, Cipher, TLSInfo, VERSION_MAP, GROUP_MAP, CIPHER_MAP

if TYPE_CHECKING:
    from ..api.server import Config as ServerConfig
    from ..api.client import Config as ClientConfig

class PyObjectHeader(ctypes.Structure):
    _fields_ = [("ob_refcnt", ctypes.c_ssize_t), ("ob_type", ctypes.c_void_p)]

libssl: ctypes.CDLL | None = None
libssl_checked = False

class TLS:
    def __init__(self, context: ssl.SSLContext):
        self.context = context

    @staticmethod
    def candidate_libssl_paths() -> list[str]:
        paths: list[str] = []

        if sys.platform == "darwin":
            try:
                dyld = ctypes.CDLL(None)
                dyld._dyld_image_count.restype = ctypes.c_uint32
                dyld._dyld_get_image_name.restype = ctypes.c_char_p
                dyld._dyld_get_image_name.argtypes = [ctypes.c_uint32]
                for index in range(dyld._dyld_image_count()):
                    name = dyld._dyld_get_image_name(index)
                    if name and b"libssl" in name:
                        path = name.decode()
                        if not (path.startswith("/usr/lib/") or path.startswith("/System/")) and path not in paths:
                            paths.append(path)
            except Exception:
                pass

        else:
            try:
                with open("/proc/self/maps", "r") as maps:
                    for line in maps:
                        if "libssl.so" in line:
                            path = line.rsplit(" ", 1)[-1].strip()
                            if path.startswith("/") and path not in paths:
                                paths.append(path)
            except OSError:
                pass

            try:
                name = ctypes.util.find_library("ssl")
                if name and name not in paths:
                    paths.append(name)
            except Exception:
                pass

        return paths

    @staticmethod
    def load_libssl() -> ctypes.CDLL | None:
        global libssl, libssl_checked
        if libssl_checked:
            return libssl
        libssl_checked = True

        for path in TLS.candidate_libssl_paths():
            try:
                lib = ctypes.CDLL(path)
                lib.OpenSSL_version.restype = ctypes.c_char_p
                lib.OpenSSL_version.argtypes = [ctypes.c_int]
                version = lib.OpenSSL_version(0)  # OPENSSL_VERSION
            except Exception:
                continue

            if version is not None and version.decode("ascii", "replace") == ssl.OPENSSL_VERSION:
                libssl = lib
                return lib

        libssl = None
        return None

    @property
    def context_pointer(self) -> int:
        offset = ctypes.sizeof(PyObjectHeader)
        if hasattr(sys, "getobjects"):
            offset += 2 * ctypes.sizeof(ctypes.c_void_p)

        ssl_context_pointer = ctypes.c_void_p.from_address(id(self.context) + offset).value

        if not ssl_context_pointer:
            raise RuntimeError("Failed to obtain SSL_CTX pointer from SSLContext")

        return ssl_context_pointer

    def set_groups(self, groups: list[Group]):
        if not groups:
            return

        if hasattr(self.context, 'set_groups'):
            self.context.set_groups(":".join([group.value for group in groups]))
            return

        libssl = TLS.load_libssl()
        if libssl is None or not hasattr(libssl, 'SSL_CTX_set1_groups_list'):
            return

        libssl.SSL_CTX_set1_groups_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libssl.SSL_CTX_set1_groups_list.restype = ctypes.c_int

        result = libssl.SSL_CTX_set1_groups_list(self.context_pointer, ":".join([group.value for group in groups]).encode('ascii'))
        if result != 1:
            raise ValueError(f"SSL_CTX_set1_groups_list failed (return={result})")

    def set_ciphers(self, ciphers: list[Cipher]):
        tls12: list[Cipher] = []
        tls13: list[Cipher] = []

        for cipher in ciphers:
            if cipher.value.startswith("TLS_"):
                tls13.append(cipher)
            else:
                tls12.append(cipher)

        self.set_ciphers_tls12(tls12)
        self.set_ciphers_tls13(tls13)

    def set_ciphers_tls12(self, ciphers: list[Cipher]):
        if not ciphers:
            return

        if hasattr(self.context, 'set_ciphers'):
            self.context.set_ciphers(":".join([cipher.value for cipher in ciphers]))
            return

        libssl = TLS.load_libssl()
        if libssl is None or not hasattr(libssl, 'SSL_CTX_set_cipher_list'):
            return

        libssl.SSL_CTX_set_cipher_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libssl.SSL_CTX_set_cipher_list.restype = ctypes.c_int

        result = libssl.SSL_CTX_set_cipher_list(self.context_pointer, ":".join([cipher.value for cipher in ciphers]).encode('ascii'))
        if result != 1:
            raise ValueError(f"SSL_CTX_set_cipher_list failed (return={result})")

    def set_ciphers_tls13(self, ciphers: list[Cipher]):
        if not ciphers:
            return

        if hasattr(self.context, 'set_ciphersuites'):
            self.context.set_ciphersuites(":".join([cipher.value for cipher in ciphers]))
            return

        libssl = TLS.load_libssl()
        if libssl is None or not hasattr(libssl, 'SSL_CTX_set_ciphersuites'):
            return

        libssl.SSL_CTX_set_ciphersuites.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        libssl.SSL_CTX_set_ciphersuites.restype = ctypes.c_int

        result = libssl.SSL_CTX_set_ciphersuites(self.context_pointer, ":".join([cipher.value for cipher in ciphers]).encode('ascii'))
        if result != 1:
            raise ValueError(f"SSL_CTX_set_ciphersuites failed (return={result})")

    @staticmethod
    def from_server_config(config: ServerConfig) -> TLS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = config.tls.minimum_version

        alpn = [p for p in config.protocols if p != "h3"]
        if alpn:
            context.set_alpn_protocols(alpn)

        if config.tls.certfile and config.tls.keyfile:
            context.load_cert_chain(config.tls.certfile, config.tls.keyfile)

        if config.tls.cafile:
            context.verify_mode = config.tls.verify_mode
            context.load_verify_locations(cafile=config.tls.cafile)

        tls = TLS(context)
        tls.set_groups(config.tls.groups)
        tls.set_ciphers(config.tls.ciphers)

        return tls

    @staticmethod
    def from_client_config(config: ClientConfig) -> TLS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = config.tls.minimum_version

        alpn = [p for p in config.protocols if p != "h3"]
        if alpn:
            context.set_alpn_protocols(alpn)

        if config.tls.verify:
            context.check_hostname = config.tls.check_hostname
            context.verify_mode = ssl.CERT_REQUIRED
            if config.tls.cafile or config.tls.capath:
                context.load_verify_locations(cafile=config.tls.cafile, capath=config.tls.capath)
            else:
                context.load_default_certs()
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        if config.tls.certfile and config.tls.keyfile:
            context.load_cert_chain(config.tls.certfile, config.tls.keyfile)

        tls = TLS(context)
        tls.set_groups(config.tls.groups)
        tls.set_ciphers(config.tls.ciphers)

        return tls

    @staticmethod
    def extract_tls_info(ssl_object: ssl.SSLObject | None) -> TLSInfo | None:
        if ssl_object is None:
            return None

        version = VERSION_MAP.get(ssl_object.version() or "")

        cipher_tuple = ssl_object.cipher()
        cipher = CIPHER_MAP.get(cipher_tuple[0]) if cipher_tuple else None

        if hasattr(ssl_object, 'group'):
            group = GROUP_MAP.get(ssl_object.group())
        else:
            group = None

        return TLSInfo(version=version, cipher=cipher, group=group)
