"""Live packet capture and protocol parsing.

Wraps Scapy with a stable Packet dataclass so the rest of the system never
imports Scapy directly. This keeps the firewall and anomaly engines pure-Python
and trivially unit-testable without raw-socket privileges.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from scapy.all import sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet as ScapyPacket


PROTO_TCP = "TCP"
PROTO_UDP = "UDP"
PROTO_ICMP = "ICMP"
PROTO_OTHER = "OTHER"

# TCP flag bits — Scapy returns the flags field as an int.
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20


@dataclass
class Packet:
    """Normalised view of a parsed network packet.

    All upper-layer fields are optional so callers can match against whatever
    the wire actually carried. `ts` is a unix timestamp captured at parse time.
    """

    ts: float
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: str = PROTO_OTHER
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: int = 0
    length: int = 0
    summary: str = ""

    @property
    def is_syn(self) -> bool:
        return bool(self.tcp_flags & TCP_SYN) and not bool(self.tcp_flags & TCP_ACK)

    @property
    def is_syn_ack(self) -> bool:
        return bool(self.tcp_flags & TCP_SYN) and bool(self.tcp_flags & TCP_ACK)

    @property
    def is_fin(self) -> bool:
        return bool(self.tcp_flags & TCP_FIN)

    @property
    def is_rst(self) -> bool:
        return bool(self.tcp_flags & TCP_RST)

    def flag_str(self) -> str:
        """Human-readable TCP flag string (e.g. 'SA' for SYN+ACK)."""
        if self.protocol != PROTO_TCP:
            return ""
        names = [
            ("F", TCP_FIN),
            ("S", TCP_SYN),
            ("R", TCP_RST),
            ("P", TCP_PSH),
            ("A", TCP_ACK),
            ("U", TCP_URG),
        ]
        return "".join(c for c, bit in names if self.tcp_flags & bit) or "-"


def parse(raw: ScapyPacket) -> Packet:
    """Translate a raw Scapy packet into our internal Packet view.

    Unknown / non-IP frames still return a Packet with whatever layers parsed.
    """
    pkt = Packet(ts=time.time(), length=len(raw), summary=raw.summary())

    if Ether in raw:
        pkt.src_mac = raw[Ether].src
        pkt.dst_mac = raw[Ether].dst

    if IP in raw:
        ip = raw[IP]
        pkt.src_ip = ip.src
        pkt.dst_ip = ip.dst

    if TCP in raw:
        tcp = raw[TCP]
        pkt.protocol = PROTO_TCP
        pkt.src_port = int(tcp.sport)
        pkt.dst_port = int(tcp.dport)
        pkt.tcp_flags = int(tcp.flags)
    elif UDP in raw:
        udp = raw[UDP]
        pkt.protocol = PROTO_UDP
        pkt.src_port = int(udp.sport)
        pkt.dst_port = int(udp.dport)
    elif ICMP in raw:
        pkt.protocol = PROTO_ICMP

    return pkt


PacketHandler = Callable[[Packet], None]


@dataclass
class Sniffer:
    """Thin wrapper over Scapy's sniff() that emits parsed Packet objects.

    Parameters
    ----------
    iface:
        Interface name (e.g. 'en0', 'eth0'). None lets Scapy pick the default.
    bpf:
        Optional Berkeley Packet Filter expression. Pushes filtering into the
        kernel so we burn fewer cycles in userspace.
    count:
        Number of packets to capture (0 = unlimited). Useful in tests.
    """

    iface: Optional[str] = None
    bpf: Optional[str] = None
    count: int = 0
    _handlers: list[PacketHandler] = field(default_factory=list)

    def subscribe(self, handler: PacketHandler) -> None:
        """Register a callback invoked for every parsed packet."""
        self._handlers.append(handler)

    def _dispatch(self, raw: ScapyPacket) -> None:
        try:
            pkt = parse(raw)
        except Exception:
            # Never let a malformed packet kill the capture loop.
            return
        for h in self._handlers:
            try:
                h(pkt)
            except Exception:
                # A bad handler should not break the others.
                continue

    def run(self) -> None:
        """Start the blocking capture loop. Requires raw-socket privileges."""
        sniff(
            iface=self.iface,
            filter=self.bpf,
            prn=self._dispatch,
            store=False,
            count=self.count,
        )
