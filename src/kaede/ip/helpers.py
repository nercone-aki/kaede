import ipaddress
from typing import Union

def address_to_bytes(ip: Union[str, bytes]) -> bytes:
    if isinstance(ip, bytes):
        return ip
    return ipaddress.ip_address(ip).packed
