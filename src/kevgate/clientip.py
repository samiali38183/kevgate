"""Resolve the client address used for logging and failure limiting.

The default is the direct peer address of the TCP connection. ``X-Forwarded-For``
is a client-supplied header, so it is honoured only when the peer is inside a
configured trusted proxy network (``KEVGATE_TRUSTED_PROXIES``). The header is
read right to left: trusted proxies are skipped and the first address that is
not trusted is the client. Anything unparsable falls back to the peer.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(entries: Iterable[str]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(e, strict=False) for e in entries)


def _is_trusted(addr: str, trusted: tuple[IPNetwork, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in trusted if net.version == ip.version)


def resolve_client_address(
    peer: str | None, forwarded_for: str | None, trusted: tuple[IPNetwork, ...]
) -> str:
    if peer is None:
        return "unknown"
    if not trusted or not forwarded_for or not _is_trusted(peer, trusted):
        return peer
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    for hop in reversed(hops):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer  # malformed header: do not guess
        if not _is_trusted(hop, trusted):
            return hop
    return peer
