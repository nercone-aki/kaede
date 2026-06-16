from __future__ import annotations

import ssl
import sys
import ctypes
import ctypes.util
from enum import Enum
from typing import TYPE_CHECKING, Literal
from dataclasses import dataclass, field
from aioquic.quic.connection import QuicConnection

if TYPE_CHECKING:
    from .server import Config as ServerConfig
    from .client import Config as ClientConfig

class Group(Enum):
    # Classic
    X25519     = "x25519"
    X448       = "x448"
    prime256v1 = "prime256v1"
    secp384r1  = "secp384r1"
    secp521r1  = "secp521r1"

    # Brainpool
    brainpoolP256r1tls13 = "brainpoolP256r1tls13"
    brainpoolP384r1tls13 = "brainpoolP384r1tls13"
    brainpoolP512r1tls13 = "brainpoolP512r1tls13"

    # FFDHE
    FFDHE2048 = "ffdhe2048"
    FFDHE3072 = "ffdhe3072"
    FFDHE4096 = "ffdhe4096"
    FFDHE6144 = "ffdhe6144"
    FFDHE8192 = "ffdhe8192"

    # Pure PQC
    MLKEM512   = "MLKEM512"
    MLKEM768   = "MLKEM768"
    MLKEM1024  = "MLKEM1024"

    # Hybrid PQC
    X25519MLKEM768     = "X25519MLKEM768"
    SECP256R1MLKEM768  = "SecP256r1MLKEM768"
    SECP384R1MLKEM1024 = "SecP384r1MLKEM1024"

class Cipher(Enum):
    # ADH (Anonymous DH)
    ADH_AES128_GCM_SHA256  = "ADH-AES128-GCM-SHA256"
    ADH_AES128_SHA         = "ADH-AES128-SHA"
    ADH_AES128_SHA256      = "ADH-AES128-SHA256"
    ADH_AES256_GCM_SHA384  = "ADH-AES256-GCM-SHA384"
    ADH_AES256_SHA         = "ADH-AES256-SHA"
    ADH_AES256_SHA256      = "ADH-AES256-SHA256"
    ADH_CAMELLIA128_SHA    = "ADH-CAMELLIA128-SHA"
    ADH_CAMELLIA128_SHA256 = "ADH-CAMELLIA128-SHA256"
    ADH_CAMELLIA256_SHA    = "ADH-CAMELLIA256-SHA"
    ADH_CAMELLIA256_SHA256 = "ADH-CAMELLIA256-SHA256"

    # AECDH (Anonymous ECDH)
    AECDH_AES128_SHA = "AECDH-AES128-SHA"
    AECDH_AES256_SHA = "AECDH-AES256-SHA"
    AECDH_NULL_SHA   = "AECDH-NULL-SHA"

    # RSA (static)
    AES128_CCM         = "AES128-CCM"
    AES128_CCM8        = "AES128-CCM8"
    AES128_GCM_SHA256  = "AES128-GCM-SHA256"
    AES128_SHA         = "AES128-SHA"
    AES128_SHA256      = "AES128-SHA256"
    AES256_CCM         = "AES256-CCM"
    AES256_CCM8        = "AES256-CCM8"
    AES256_GCM_SHA384  = "AES256-GCM-SHA384"
    AES256_SHA         = "AES256-SHA"
    AES256_SHA256      = "AES256-SHA256"
    ARIA128_GCM_SHA256 = "ARIA128-GCM-SHA256"
    ARIA256_GCM_SHA384 = "ARIA256-GCM-SHA384"
    CAMELLIA128_SHA    = "CAMELLIA128-SHA"
    CAMELLIA128_SHA256 = "CAMELLIA128-SHA256"
    CAMELLIA256_SHA    = "CAMELLIA256-SHA"
    CAMELLIA256_SHA256 = "CAMELLIA256-SHA256"

    # DHE-DSS
    DHE_DSS_AES128_GCM_SHA256  = "DHE-DSS-AES128-GCM-SHA256"
    DHE_DSS_AES128_SHA         = "DHE-DSS-AES128-SHA"
    DHE_DSS_AES128_SHA256      = "DHE-DSS-AES128-SHA256"
    DHE_DSS_AES256_GCM_SHA384  = "DHE-DSS-AES256-GCM-SHA384"
    DHE_DSS_AES256_SHA         = "DHE-DSS-AES256-SHA"
    DHE_DSS_AES256_SHA256      = "DHE-DSS-AES256-SHA256"
    DHE_DSS_ARIA128_GCM_SHA256 = "DHE-DSS-ARIA128-GCM-SHA256"
    DHE_DSS_ARIA256_GCM_SHA384 = "DHE-DSS-ARIA256-GCM-SHA384"
    DHE_DSS_CAMELLIA128_SHA    = "DHE-DSS-CAMELLIA128-SHA"
    DHE_DSS_CAMELLIA128_SHA256 = "DHE-DSS-CAMELLIA128-SHA256"
    DHE_DSS_CAMELLIA256_SHA    = "DHE-DSS-CAMELLIA256-SHA"
    DHE_DSS_CAMELLIA256_SHA256 = "DHE-DSS-CAMELLIA256-SHA256"

    # DHE-PSK
    DHE_PSK_AES128_CBC_SHA     = "DHE-PSK-AES128-CBC-SHA"
    DHE_PSK_AES128_CBC_SHA256  = "DHE-PSK-AES128-CBC-SHA256"
    DHE_PSK_AES128_CCM         = "DHE-PSK-AES128-CCM"
    DHE_PSK_AES128_CCM8        = "DHE-PSK-AES128-CCM8"
    DHE_PSK_AES128_GCM_SHA256  = "DHE-PSK-AES128-GCM-SHA256"
    DHE_PSK_AES256_CBC_SHA     = "DHE-PSK-AES256-CBC-SHA"
    DHE_PSK_AES256_CBC_SHA384  = "DHE-PSK-AES256-CBC-SHA384"
    DHE_PSK_AES256_CCM         = "DHE-PSK-AES256-CCM"
    DHE_PSK_AES256_CCM8        = "DHE-PSK-AES256-CCM8"
    DHE_PSK_AES256_GCM_SHA384  = "DHE-PSK-AES256-GCM-SHA384"
    DHE_PSK_ARIA128_GCM_SHA256 = "DHE-PSK-ARIA128-GCM-SHA256"
    DHE_PSK_ARIA256_GCM_SHA384 = "DHE-PSK-ARIA256-GCM-SHA384"
    DHE_PSK_CAMELLIA128_SHA256 = "DHE-PSK-CAMELLIA128-SHA256"
    DHE_PSK_CAMELLIA256_SHA384 = "DHE-PSK-CAMELLIA256-SHA384"
    DHE_PSK_CHACHA20_POLY1305  = "DHE-PSK-CHACHA20-POLY1305"
    DHE_PSK_NULL_SHA           = "DHE-PSK-NULL-SHA"
    DHE_PSK_NULL_SHA256        = "DHE-PSK-NULL-SHA256"
    DHE_PSK_NULL_SHA384        = "DHE-PSK-NULL-SHA384"

    # DHE-RSA
    DHE_RSA_AES128_CCM         = "DHE-RSA-AES128-CCM"
    DHE_RSA_AES128_CCM8        = "DHE-RSA-AES128-CCM8"
    DHE_RSA_AES128_GCM_SHA256  = "DHE-RSA-AES128-GCM-SHA256"
    DHE_RSA_AES128_SHA         = "DHE-RSA-AES128-SHA"
    DHE_RSA_AES128_SHA256      = "DHE-RSA-AES128-SHA256"
    DHE_RSA_AES256_CCM         = "DHE-RSA-AES256-CCM"
    DHE_RSA_AES256_CCM8        = "DHE-RSA-AES256-CCM8"
    DHE_RSA_AES256_GCM_SHA384  = "DHE-RSA-AES256-GCM-SHA384"
    DHE_RSA_AES256_SHA         = "DHE-RSA-AES256-SHA"
    DHE_RSA_AES256_SHA256      = "DHE-RSA-AES256-SHA256"
    DHE_RSA_ARIA128_GCM_SHA256 = "DHE-RSA-ARIA128-GCM-SHA256"
    DHE_RSA_ARIA256_GCM_SHA384 = "DHE-RSA-ARIA256-GCM-SHA384"
    DHE_RSA_CAMELLIA128_SHA    = "DHE-RSA-CAMELLIA128-SHA"
    DHE_RSA_CAMELLIA128_SHA256 = "DHE-RSA-CAMELLIA128-SHA256"
    DHE_RSA_CAMELLIA256_SHA    = "DHE-RSA-CAMELLIA256-SHA"
    DHE_RSA_CAMELLIA256_SHA256 = "DHE-RSA-CAMELLIA256-SHA256"
    DHE_RSA_CHACHA20_POLY1305  = "DHE-RSA-CHACHA20-POLY1305"

    # ECDHE-ECDSA
    ECDHE_ECDSA_AES128_CCM         = "ECDHE-ECDSA-AES128-CCM"
    ECDHE_ECDSA_AES128_CCM8        = "ECDHE-ECDSA-AES128-CCM8"
    ECDHE_ECDSA_AES128_GCM_SHA256  = "ECDHE-ECDSA-AES128-GCM-SHA256"
    ECDHE_ECDSA_AES128_SHA         = "ECDHE-ECDSA-AES128-SHA"
    ECDHE_ECDSA_AES128_SHA256      = "ECDHE-ECDSA-AES128-SHA256"
    ECDHE_ECDSA_AES256_CCM         = "ECDHE-ECDSA-AES256-CCM"
    ECDHE_ECDSA_AES256_CCM8        = "ECDHE-ECDSA-AES256-CCM8"
    ECDHE_ECDSA_AES256_GCM_SHA384  = "ECDHE-ECDSA-AES256-GCM-SHA384"
    ECDHE_ECDSA_AES256_SHA         = "ECDHE-ECDSA-AES256-SHA"
    ECDHE_ECDSA_AES256_SHA384      = "ECDHE-ECDSA-AES256-SHA384"
    ECDHE_ECDSA_ARIA128_GCM_SHA256 = "ECDHE-ECDSA-ARIA128-GCM-SHA256"
    ECDHE_ECDSA_ARIA256_GCM_SHA384 = "ECDHE-ECDSA-ARIA256-GCM-SHA384"
    ECDHE_ECDSA_CAMELLIA128_SHA256 = "ECDHE-ECDSA-CAMELLIA128-SHA256"
    ECDHE_ECDSA_CAMELLIA256_SHA384 = "ECDHE-ECDSA-CAMELLIA256-SHA384"
    ECDHE_ECDSA_CHACHA20_POLY1305  = "ECDHE-ECDSA-CHACHA20-POLY1305"
    ECDHE_ECDSA_NULL_SHA           = "ECDHE-ECDSA-NULL-SHA"

    # ECDHE-PSK
    ECDHE_PSK_AES128_CBC_SHA     = "ECDHE-PSK-AES128-CBC-SHA"
    ECDHE_PSK_AES128_CBC_SHA256  = "ECDHE-PSK-AES128-CBC-SHA256"
    ECDHE_PSK_AES256_CBC_SHA     = "ECDHE-PSK-AES256-CBC-SHA"
    ECDHE_PSK_AES256_CBC_SHA384  = "ECDHE-PSK-AES256-CBC-SHA384"
    ECDHE_PSK_CAMELLIA128_SHA256 = "ECDHE-PSK-CAMELLIA128-SHA256"
    ECDHE_PSK_CAMELLIA256_SHA384 = "ECDHE-PSK-CAMELLIA256-SHA384"
    ECDHE_PSK_CHACHA20_POLY1305  = "ECDHE-PSK-CHACHA20-POLY1305"
    ECDHE_PSK_NULL_SHA           = "ECDHE-PSK-NULL-SHA"
    ECDHE_PSK_NULL_SHA256        = "ECDHE-PSK-NULL-SHA256"
    ECDHE_PSK_NULL_SHA384        = "ECDHE-PSK-NULL-SHA384"

    # ECDHE-RSA
    ECDHE_RSA_AES128_GCM_SHA256  = "ECDHE-RSA-AES128-GCM-SHA256"
    ECDHE_RSA_AES128_SHA         = "ECDHE-RSA-AES128-SHA"
    ECDHE_RSA_AES128_SHA256      = "ECDHE-RSA-AES128-SHA256"
    ECDHE_RSA_AES256_GCM_SHA384  = "ECDHE-RSA-AES256-GCM-SHA384"
    ECDHE_RSA_AES256_SHA         = "ECDHE-RSA-AES256-SHA"
    ECDHE_RSA_AES256_SHA384      = "ECDHE-RSA-AES256-SHA384"
    ECDHE_RSA_ARIA128_GCM_SHA256 = "ECDHE-RSA-ARIA128-GCM-SHA256"
    ECDHE_RSA_ARIA256_GCM_SHA384 = "ECDHE-RSA-ARIA256-GCM-SHA384"
    ECDHE_RSA_CAMELLIA128_SHA256 = "ECDHE-RSA-CAMELLIA128-SHA256"
    ECDHE_RSA_CAMELLIA256_SHA384 = "ECDHE-RSA-CAMELLIA256-SHA384"
    ECDHE_RSA_CHACHA20_POLY1305  = "ECDHE-RSA-CHACHA20-POLY1305"
    ECDHE_RSA_NULL_SHA           = "ECDHE-RSA-NULL-SHA"

    # NULL
    NULL_MD5    = "NULL-MD5"
    NULL_SHA    = "NULL-SHA"
    NULL_SHA256 = "NULL-SHA256"

    # PSK
    PSK_AES128_CBC_SHA     = "PSK-AES128-CBC-SHA"
    PSK_AES128_CBC_SHA256  = "PSK-AES128-CBC-SHA256"
    PSK_AES128_CCM         = "PSK-AES128-CCM"
    PSK_AES128_CCM8        = "PSK-AES128-CCM8"
    PSK_AES128_GCM_SHA256  = "PSK-AES128-GCM-SHA256"
    PSK_AES256_CBC_SHA     = "PSK-AES256-CBC-SHA"
    PSK_AES256_CBC_SHA384  = "PSK-AES256-CBC-SHA384"
    PSK_AES256_CCM         = "PSK-AES256-CCM"
    PSK_AES256_CCM8        = "PSK-AES256-CCM8"
    PSK_AES256_GCM_SHA384  = "PSK-AES256-GCM-SHA384"
    PSK_ARIA128_GCM_SHA256 = "PSK-ARIA128-GCM-SHA256"
    PSK_ARIA256_GCM_SHA384 = "PSK-ARIA256-GCM-SHA384"
    PSK_CAMELLIA128_SHA256 = "PSK-CAMELLIA128-SHA256"
    PSK_CAMELLIA256_SHA384 = "PSK-CAMELLIA256-SHA384"
    PSK_CHACHA20_POLY1305  = "PSK-CHACHA20-POLY1305"
    PSK_NULL_SHA           = "PSK-NULL-SHA"
    PSK_NULL_SHA256        = "PSK-NULL-SHA256"
    PSK_NULL_SHA384        = "PSK-NULL-SHA384"

    # RSA-PSK
    RSA_PSK_AES128_CBC_SHA     = "RSA-PSK-AES128-CBC-SHA"
    RSA_PSK_AES128_CBC_SHA256  = "RSA-PSK-AES128-CBC-SHA256"
    RSA_PSK_AES128_GCM_SHA256  = "RSA-PSK-AES128-GCM-SHA256"
    RSA_PSK_AES256_CBC_SHA     = "RSA-PSK-AES256-CBC-SHA"
    RSA_PSK_AES256_CBC_SHA384  = "RSA-PSK-AES256-CBC-SHA384"
    RSA_PSK_AES256_GCM_SHA384  = "RSA-PSK-AES256-GCM-SHA384"
    RSA_PSK_ARIA128_GCM_SHA256 = "RSA-PSK-ARIA128-GCM-SHA256"
    RSA_PSK_ARIA256_GCM_SHA384 = "RSA-PSK-ARIA256-GCM-SHA384"
    RSA_PSK_CAMELLIA128_SHA256 = "RSA-PSK-CAMELLIA128-SHA256"
    RSA_PSK_CAMELLIA256_SHA384 = "RSA-PSK-CAMELLIA256-SHA384"
    RSA_PSK_CHACHA20_POLY1305  = "RSA-PSK-CHACHA20-POLY1305"
    RSA_PSK_NULL_SHA           = "RSA-PSK-NULL-SHA"
    RSA_PSK_NULL_SHA256        = "RSA-PSK-NULL-SHA256"
    RSA_PSK_NULL_SHA384        = "RSA-PSK-NULL-SHA384"

    # SRP
    SRP_AES_128_CBC_SHA     = "SRP-AES-128-CBC-SHA"
    SRP_AES_256_CBC_SHA     = "SRP-AES-256-CBC-SHA"
    SRP_DSS_AES_128_CBC_SHA = "SRP-DSS-AES-128-CBC-SHA"
    SRP_DSS_AES_256_CBC_SHA = "SRP-DSS-AES-256-CBC-SHA"
    SRP_RSA_AES_128_CBC_SHA = "SRP-RSA-AES-128-CBC-SHA"
    SRP_RSA_AES_256_CBC_SHA = "SRP-RSA-AES-256-CBC-SHA"

    # TLS 1.3
    TLS_AES_128_GCM_SHA256       = "TLS_AES_128_GCM_SHA256"
    TLS_AES_256_GCM_SHA384       = "TLS_AES_256_GCM_SHA384"
    TLS_CHACHA20_POLY1305_SHA256 = "TLS_CHACHA20_POLY1305_SHA256"

VERSION_MAP: dict[str, Literal["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]] = {
    "TLSv1":   "TLSv1.0",
    "TLSv1.1": "TLSv1.1",
    "TLSv1.2": "TLSv1.2",
    "TLSv1.3": "TLSv1.3"
}

GROUP_MAP: dict[str, Group] = {
    "x25519":               Group.X25519,
    "X25519":               Group.X25519,
    "x448":                 Group.X448,
    "prime256v1":           Group.prime256v1,
    "secp256r1":            Group.prime256v1,
    "P-256":                Group.prime256v1,
    "secp384r1":            Group.secp384r1,
    "P-384":                Group.secp384r1,
    "secp521r1":            Group.secp521r1,
    "P-521":                Group.secp521r1,
    "brainpoolP256r1tls13": Group.brainpoolP256r1tls13,
    "brainpoolP384r1tls13": Group.brainpoolP384r1tls13,
    "brainpoolP512r1tls13": Group.brainpoolP512r1tls13,
    "ffdhe2048":            Group.FFDHE2048,
    "ffdhe3072":            Group.FFDHE3072,
    "ffdhe4096":            Group.FFDHE4096,
    "ffdhe6144":            Group.FFDHE6144,
    "ffdhe8192":            Group.FFDHE8192,
    "MLKEM512":             Group.MLKEM512,
    "MLKEM768":             Group.MLKEM768,
    "MLKEM1024":            Group.MLKEM1024,
    "X25519MLKEM768":       Group.X25519MLKEM768,
    "SecP256r1MLKEM768":    Group.SECP256R1MLKEM768,
    "SecP384r1MLKEM1024":   Group.SECP384R1MLKEM1024
}

CIPHER_MAP: dict[str, Cipher] = {c.value: c for c in Cipher}

@dataclass
class TLSInfo:
    version: Literal["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"] | None
    group: Group | None
    cipher: Cipher | None

@dataclass
class TLSServerConfig:
    certfile: str | None = None
    keyfile: str | None = None
    cafile: str | None = None

    verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    ciphers: list[Cipher] = field(default_factory=lambda: [
        # TLS 1.3
        Cipher.TLS_AES_128_GCM_SHA256,
        Cipher.TLS_AES_256_GCM_SHA384,
        Cipher.TLS_CHACHA20_POLY1305_SHA256,
        # TLS 1.2 (ECDSA)
        Cipher.ECDHE_ECDSA_AES128_GCM_SHA256,
        Cipher.ECDHE_ECDSA_AES256_GCM_SHA384,
        Cipher.ECDHE_ECDSA_CHACHA20_POLY1305,
        # TLS 1.2 (RSA)
        Cipher.ECDHE_RSA_AES128_GCM_SHA256,
        Cipher.ECDHE_RSA_AES256_GCM_SHA384,
        Cipher.ECDHE_RSA_CHACHA20_POLY1305
    ])
    groups: list[Group] = field(default_factory=lambda: [
        # PQC (Hybrid)
        Group.X25519MLKEM768,
        Group.SECP384R1MLKEM1024,
        Group.SECP256R1MLKEM768,
        # PQC (Pure)
        Group.MLKEM1024,
        Group.MLKEM768,
        # Classic
        Group.X25519,
        Group.prime256v1,
        Group.secp384r1
    ])

@dataclass
class TLSClientConfig:
    verify: bool = True
    cafile: str | None = None
    capath: str | None = None

    check_hostname: bool = True
    minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2

    certfile: str | None = None
    keyfile: str | None = None

    ciphers: list[Cipher] = field(default_factory=lambda: [
        # TLS 1.3
        Cipher.TLS_AES_128_GCM_SHA256,
        Cipher.TLS_AES_256_GCM_SHA384,
        Cipher.TLS_CHACHA20_POLY1305_SHA256,
        # TLS 1.2 (ECDSA)
        Cipher.ECDHE_ECDSA_AES128_GCM_SHA256,
        Cipher.ECDHE_ECDSA_AES256_GCM_SHA384,
        Cipher.ECDHE_ECDSA_CHACHA20_POLY1305,
        # TLS 1.2 (RSA)
        Cipher.ECDHE_RSA_AES128_GCM_SHA256,
        Cipher.ECDHE_RSA_AES256_GCM_SHA384,
        Cipher.ECDHE_RSA_CHACHA20_POLY1305
    ])
    groups: list[Group] = field(default_factory=lambda: [
        # PQC (Hybrid)
        Group.X25519MLKEM768,
        Group.SECP384R1MLKEM1024,
        Group.SECP256R1MLKEM768,
        # PQC (Pure)
        Group.MLKEM1024,
        Group.MLKEM768,
        # Classic
        Group.X25519,
        Group.prime256v1,
        Group.secp384r1
    ])

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
    def extract_tls_info_h3(quic_connection: QuicConnection) -> TLSInfo:
        cipher = None
        try:
            cipher = CIPHER_MAP.get("TLS_" + quic_connection.tls.key_schedule.cipher_suite.name)
        except Exception:
            pass
        return TLSInfo(version="TLSv1.3", cipher=cipher, group=None)

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
