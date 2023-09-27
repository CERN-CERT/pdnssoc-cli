

from ipaddress import ip_address, IPv4Address, IPv6Address

def validIPAddress(IP: str) -> str:
    try:
        return type(ip_address(IP)) is IPv4Address or type(ip_address(IP)) is IPv6Address
    except ValueError:
        return False