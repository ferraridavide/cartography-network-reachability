from __future__ import annotations

import ipaddress
from typing import Iterable

def ipv4_network(value: str | None) -> ipaddress.IPv4Network | None:
    if not value or "." not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def ipv4_address(value: str | None) -> ipaddress.IPv4Address | None:
    if not value or "." not in value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def network_intersection(
    a: ipaddress.IPv4Network, b: ipaddress.IPv4Network
) -> ipaddress.IPv4Network | None:
    if not a.overlaps(b):
        return None
    if a.subnet_of(b):
        return a
    if b.subnet_of(a):
        return b
    # IPv4 CIDRs are either nested or disjoint, so this is defensive.
    return None


def subtract_networks(
    networks: Iterable[ipaddress.IPv4Network], remove: ipaddress.IPv4Network
) -> list[ipaddress.IPv4Network]:
    remaining: list[ipaddress.IPv4Network] = []
    for network in networks:
        overlap = network_intersection(network, remove)
        if overlap is None:
            remaining.append(network)
        elif overlap == network:
            continue
        else:
            remaining.extend(network.address_exclude(overlap))
    return remaining
