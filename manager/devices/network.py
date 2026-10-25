"""Closed network report validation; claims never establish device identity."""
import ipaddress
import re

from .contracts import DeviceError, canonical_uuid


def ip_literal(value):
    """Parse a single unscoped literal, including IPv4-mapped normalization."""
    try:
        if type(value) is not str or not value or value != value.strip() or "%" in value:
            raise ValueError
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return address
    except ValueError:
        raise DeviceError("invalid_request") from None


def normalize_ip(value):
    address = ip_literal(value)
    if address.is_loopback or address.is_unspecified or address.is_multicast or address.is_link_local:
        raise DeviceError("invalid_request")
    return str(address)


def network_heartbeat_input(data):
    if (type(data) is not dict or set(data) != {"protocol", "device_id", "generation", "network"}
            or data["protocol"] != "2.1" or type(data["generation"]) is not int
            or not 1 <= data["generation"] <= 2147483647):
        raise DeviceError("invalid_request")
    canonical_uuid(data["device_id"])
    network = data["network"]
    if (type(network) is not dict or set(network) != {"collection_status", "reported_ips", "truncated", "agent_version"}
            or type(network["truncated"]) is not bool or type(network["agent_version"]) is not str
            or len(network["agent_version"]) > 32
            or not re.fullmatch(r"(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})", network["agent_version"])):
        raise DeviceError("invalid_request")
    ips = network["reported_ips"]
    if network["collection_status"] == "unavailable":
        if ips is not None or network["truncated"]:
            raise DeviceError("invalid_request")
    elif network["collection_status"] == "ok":
        if type(ips) is not list or len(ips) > 32:
            raise DeviceError("invalid_request")
        ips = sorted({normalize_ip(value) for value in ips}, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value).packed))
        if network["truncated"] and len(ips) != 32:
            raise DeviceError("invalid_request")
    else:
        raise DeviceError("invalid_request")
    return data | {"network": network | {"reported_ips": ips}}
