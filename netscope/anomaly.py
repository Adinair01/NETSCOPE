"""Sliding-window anomaly detectors.

Implements two classic detectors that fire alerts based on per-source-IP
behaviour observed within a configurable time window:

* PortScanDetector  — unique destination ports seen from one source.
* SynFloodDetector  — raw SYN count from one source to one destination.

Both share the same sliding-window primitive: a per-key deque of (ts, value)
events, evicted by timestamp on every observation. This keeps memory bounded
without a separate cleanup pass.

The detectors are decoupled from the rest of NetScope — they consume Packet
objects and emit Alert objects via callbacks. Wire them into the dashboard
or the firewall as you like.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Optional

from netscope.sniffer import PROTO_TCP, Packet


@dataclass(frozen=True)
class Alert:
    """An anomaly the detectors believe is worth surfacing."""

    kind: str            # 'port_scan' | 'syn_flood'
    src_ip: str
    dst_ip: Optional[str]
    detail: str
    ts: float


AlertHandler = Callable[[Alert], None]


# ---------------------------------------------------------------------------
# Port scan
# ---------------------------------------------------------------------------


@dataclass
class PortScanDetector:
    """Flags a source IP that probes many distinct ports inside `window` seconds.

    `cooldown` suppresses repeat alerts for the same source until the window
    rolls over — otherwise a scanner trips an alert on every packet after the
    threshold is crossed.
    """

    window: float = 10.0
    threshold: int = 20
    cooldown: float = 30.0

    _seen: dict[str, Deque[tuple[float, int]]] = field(
        default_factory=lambda: defaultdict(deque), init=False, repr=False,
    )
    _last_alert: dict[str, float] = field(default_factory=dict, init=False, repr=False)

    def observe(self, pkt: Packet) -> Optional[Alert]:
        if not pkt.src_ip or pkt.dst_port is None:
            return None

        now = pkt.ts or time.time()
        events = self._seen[pkt.src_ip]
        events.append((now, pkt.dst_port))
        self._evict(events, now - self.window)

        unique_ports = {port for _, port in events}
        if len(unique_ports) < self.threshold:
            return None

        last = self._last_alert.get(pkt.src_ip, 0.0)
        if now - last < self.cooldown:
            return None
        self._last_alert[pkt.src_ip] = now

        return Alert(
            kind="port_scan",
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            detail=f"{len(unique_ports)} unique ports in {self.window:.0f}s",
            ts=now,
        )

    @staticmethod
    def _evict(events: Deque[tuple[float, int]], cutoff: float) -> None:
        while events and events[0][0] < cutoff:
            events.popleft()


# ---------------------------------------------------------------------------
# SYN flood
# ---------------------------------------------------------------------------


@dataclass
class SynFloodDetector:
    """Flags a (src, dst) pair sending too many SYNs inside `window` seconds.

    We key on the destination too: a busy proxy might legitimately produce
    many SYNs across many destinations, but a flood is highly concentrated.
    """

    window: float = 5.0
    threshold: int = 100
    cooldown: float = 15.0

    _seen: dict[tuple[str, str], Deque[float]] = field(
        default_factory=lambda: defaultdict(deque), init=False, repr=False,
    )
    _last_alert: dict[tuple[str, str], float] = field(
        default_factory=dict, init=False, repr=False,
    )

    def observe(self, pkt: Packet) -> Optional[Alert]:
        if pkt.protocol != PROTO_TCP or not pkt.is_syn:
            return None
        if not (pkt.src_ip and pkt.dst_ip):
            return None

        key = (pkt.src_ip, pkt.dst_ip)
        now = pkt.ts or time.time()
        events = self._seen[key]
        events.append(now)
        cutoff = now - self.window
        while events and events[0] < cutoff:
            events.popleft()

        if len(events) < self.threshold:
            return None

        if now - self._last_alert.get(key, 0.0) < self.cooldown:
            return None
        self._last_alert[key] = now

        return Alert(
            kind="syn_flood",
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            detail=f"{len(events)} SYNs in {self.window:.0f}s",
            ts=now,
        )


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------


@dataclass
class AnomalyDetector:
    """Bundles individual detectors behind one observe() entrypoint."""

    port_scan: PortScanDetector = field(default_factory=PortScanDetector)
    syn_flood: SynFloodDetector = field(default_factory=SynFloodDetector)
    _handlers: list[AlertHandler] = field(default_factory=list, init=False, repr=False)
    _count: int = field(default=0, init=False, repr=False)

    def subscribe(self, handler: AlertHandler) -> None:
        self._handlers.append(handler)

    def observe(self, pkt: Packet) -> list[Alert]:
        fired: list[Alert] = []
        for det in (self.port_scan, self.syn_flood):
            alert = det.observe(pkt)
            if alert:
                fired.append(alert)
        for alert in fired:
            self._count += 1
            for h in self._handlers:
                try:
                    h(alert)
                except Exception:
                    continue
        return fired

    @property
    def alert_count(self) -> int:
        return self._count
