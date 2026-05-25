"""Stateful firewall: 5-tuple rule matching plus connection tracking.

Design notes
------------
* Rules are evaluated in order; first match wins. Default verdict is DENY.
* `*` (or omitted field) is a wildcard for that dimension of the 5-tuple.
* Ports may be a single int, a list of ints, or a 'lo-hi' range string.
* IPs may be a literal address or a CIDR block.
* Stateful tracking: when a rule allows a packet we record the connection
  5-tuple. Subsequent packets in either direction match the connection table
  and bypass the rule scan. TTL expiry is run inline on every evaluate() call
  so we never need a background reaper thread.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional, Union

import yaml

from netscope.sniffer import PROTO_TCP, Packet


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


PortSpec = Union[int, str, list[int], None]
"""A port match: int, list of ints, 'lo-hi' range string, or None for any."""


@dataclass(frozen=True)
class Rule:
    """A single firewall rule. Any field set to None acts as a wildcard."""

    name: str
    action: Verdict
    protocol: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: PortSpec = None
    dst_port: PortSpec = None

    def matches(self, pkt: Packet) -> bool:
        if self.protocol and pkt.protocol != self.protocol.upper():
            return False
        if not _ip_match(self.src_ip, pkt.src_ip):
            return False
        if not _ip_match(self.dst_ip, pkt.dst_ip):
            return False
        if not _port_match(self.src_port, pkt.src_port):
            return False
        if not _port_match(self.dst_port, pkt.dst_port):
            return False
        return True


# ---------------------------------------------------------------------------
# Match helpers
# ---------------------------------------------------------------------------


def _ip_match(spec: Optional[str], actual: Optional[str]) -> bool:
    """True if `actual` falls inside `spec` (literal, CIDR, or wildcard)."""
    if spec is None or spec == "*":
        return True
    if actual is None:
        return False
    try:
        network = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        # Treat as literal string compare for non-IP rules (e.g. macros).
        return spec == actual
    try:
        return ipaddress.ip_address(actual) in network
    except ValueError:
        return False


def _port_match(spec: PortSpec, actual: Optional[int]) -> bool:
    if spec is None or spec == "*":
        return True
    if actual is None:
        return False
    if isinstance(spec, int):
        return actual == spec
    if isinstance(spec, list):
        return actual in spec
    if isinstance(spec, str):
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            return int(lo) <= actual <= int(hi)
        return actual == int(spec)
    return False


# ---------------------------------------------------------------------------
# Connection tracking
# ---------------------------------------------------------------------------

ConnKey = tuple[str, str, str, int, int]
"""(protocol, src_ip, dst_ip, src_port, dst_port). Hashable, reversible."""


def _conn_key(pkt: Packet) -> Optional[ConnKey]:
    if not (pkt.src_ip and pkt.dst_ip and pkt.src_port and pkt.dst_port):
        return None
    return (pkt.protocol, pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)


def _reverse(key: ConnKey) -> ConnKey:
    proto, sip, dip, sport, dport = key
    return (proto, dip, sip, dport, sport)


@dataclass
class _Conn:
    last_seen: float
    packets: int = 0


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------


@dataclass
class Decision:
    """The result of evaluating one packet."""

    verdict: Verdict
    rule: Optional[str]   # rule name, or 'established' / 'default-deny'
    pkt: Packet


@dataclass
class Firewall:
    """Stateless rule engine with stateful connection tracking on top."""

    rules: list[Rule] = field(default_factory=list)
    default: Verdict = Verdict.DENY
    conn_ttl: float = 120.0

    _conns: dict[ConnKey, _Conn] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _stats: dict[str, int] = field(
        default_factory=lambda: {"allow": 0, "deny": 0, "established": 0},
        init=False, repr=False,
    )

    # -- rule loading -------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: Union[str, Path]) -> "Firewall":
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        return cls.from_dict(doc)

    @classmethod
    def from_dict(cls, doc: dict) -> "Firewall":
        rules = [_rule_from_dict(r) for r in doc.get("rules", [])]
        default = Verdict(doc.get("default", "DENY").upper())
        ttl = float(doc.get("conn_ttl", 120.0))
        return cls(rules=rules, default=default, conn_ttl=ttl)

    # -- evaluation ---------------------------------------------------------

    def evaluate(self, pkt: Packet) -> Decision:
        """Return the verdict for one packet and update connection state."""
        now = pkt.ts or time.time()
        with self._lock:
            self._expire(now)

            key = _conn_key(pkt)
            if key and self._is_established(key, now):
                self._touch(key, now)
                self._stats["established"] += 1
                self._stats["allow"] += 1
                return Decision(Verdict.ALLOW, "established", pkt)

            for rule in self.rules:
                if rule.matches(pkt):
                    if rule.action is Verdict.ALLOW and key:
                        self._track(key, now)
                    self._stats[rule.action.value.lower()] += 1
                    return Decision(rule.action, rule.name, pkt)

            self._stats[self.default.value.lower()] += 1
            return Decision(self.default, "default", pkt)

    # -- stateful internals -------------------------------------------------

    def _track(self, key: ConnKey, now: float) -> None:
        conn = self._conns.get(key) or _Conn(last_seen=now)
        conn.last_seen = now
        conn.packets += 1
        self._conns[key] = conn

    def _touch(self, key: ConnKey, now: float) -> None:
        for k in (key, _reverse(key)):
            if k in self._conns:
                self._conns[k].last_seen = now
                self._conns[k].packets += 1
                return

    def _is_established(self, key: ConnKey, now: float) -> bool:
        for k in (key, _reverse(key)):
            conn = self._conns.get(k)
            if conn and (now - conn.last_seen) <= self.conn_ttl:
                return True
        return False

    def _expire(self, now: float) -> None:
        cutoff = now - self.conn_ttl
        dead = [k for k, c in self._conns.items() if c.last_seen < cutoff]
        for k in dead:
            del self._conns[k]

    # -- introspection ------------------------------------------------------

    @property
    def active_connections(self) -> int:
        with self._lock:
            return len(self._conns)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._stats) | {"active_connections": len(self._conns)}


# ---------------------------------------------------------------------------
# YAML deserialisation
# ---------------------------------------------------------------------------


def _rule_from_dict(d: dict) -> Rule:
    action = Verdict(str(d["action"]).upper())
    return Rule(
        name=d["name"],
        action=action,
        protocol=d.get("protocol"),
        src_ip=_norm(d.get("src_ip")),
        dst_ip=_norm(d.get("dst_ip")),
        src_port=_norm_port(d.get("src_port")),
        dst_port=_norm_port(d.get("dst_port")),
    )


def _norm(v):
    if v in (None, "*", "any", "ANY"):
        return None
    return v


def _norm_port(v) -> PortSpec:
    if v in (None, "*", "any", "ANY"):
        return None
    if isinstance(v, (int, list)):
        return v
    return str(v)
