"""End-to-end unit tests for the firewall and anomaly engines.

These tests deliberately avoid touching Scapy or raw sockets — they construct
Packet objects directly. That keeps CI fast and lets us test the pure logic
without root privileges.
"""

from __future__ import annotations

import time

import pytest

from netscope.anomaly import AnomalyDetector, PortScanDetector, SynFloodDetector
from netscope.firewall import Firewall, Rule, Verdict
from netscope.sniffer import (
    PROTO_ICMP,
    PROTO_TCP,
    PROTO_UDP,
    TCP_ACK,
    TCP_SYN,
    Packet,
)


# ---------------------------------------------------------------------------
# Packet factory
# ---------------------------------------------------------------------------


def mkpkt(
    *,
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=40000,
    dst_port=443,
    protocol=PROTO_TCP,
    flags=TCP_SYN,
    ts=None,
):
    return Packet(
        ts=ts if ts is not None else time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        tcp_flags=flags,
        length=64,
    )


# ---------------------------------------------------------------------------
# Rule matching
# ---------------------------------------------------------------------------


class TestRuleMatching:
    def test_exact_port_match(self):
        rule = Rule(name="https", action=Verdict.ALLOW, protocol="TCP", dst_port=443)
        assert rule.matches(mkpkt(dst_port=443))
        assert not rule.matches(mkpkt(dst_port=80))

    def test_port_list(self):
        rule = Rule(name="smb", action=Verdict.DENY, protocol="TCP", dst_port=[139, 445])
        assert rule.matches(mkpkt(dst_port=139))
        assert rule.matches(mkpkt(dst_port=445))
        assert not rule.matches(mkpkt(dst_port=22))

    def test_port_range(self):
        rule = Rule(name="ephemeral", action=Verdict.ALLOW, dst_port="49152-65535")
        assert rule.matches(mkpkt(dst_port=50000))
        assert not rule.matches(mkpkt(dst_port=22))

    def test_cidr_match(self):
        rule = Rule(name="lan", action=Verdict.ALLOW, src_ip="10.0.0.0/8")
        assert rule.matches(mkpkt(src_ip="10.5.6.7"))
        assert not rule.matches(mkpkt(src_ip="192.168.1.1"))

    def test_protocol_filter(self):
        rule = Rule(name="udp-only", action=Verdict.ALLOW, protocol="UDP")
        assert rule.matches(mkpkt(protocol=PROTO_UDP, flags=0))
        assert not rule.matches(mkpkt(protocol=PROTO_TCP))

    def test_wildcard_fields(self):
        rule = Rule(name="any", action=Verdict.ALLOW)
        assert rule.matches(mkpkt())
        assert rule.matches(mkpkt(protocol=PROTO_ICMP, src_port=None, dst_port=None))


# ---------------------------------------------------------------------------
# Firewall behaviour
# ---------------------------------------------------------------------------


class TestFirewall:
    def test_default_deny(self):
        fw = Firewall(rules=[], default=Verdict.DENY)
        d = fw.evaluate(mkpkt())
        assert d.verdict is Verdict.DENY
        assert d.rule == "default"

    def test_first_match_wins(self):
        fw = Firewall(
            rules=[
                Rule(name="block-all", action=Verdict.DENY),
                Rule(name="allow-https", action=Verdict.ALLOW, dst_port=443),
            ],
        )
        assert fw.evaluate(mkpkt()).rule == "block-all"

    def test_yaml_roundtrip(self):
        doc = {
            "default": "DENY",
            "conn_ttl": 60,
            "rules": [
                {"name": "dns", "action": "ALLOW", "protocol": "UDP", "dst_port": 53},
                {"name": "https", "action": "ALLOW", "protocol": "TCP", "dst_port": 443},
            ],
        }
        fw = Firewall.from_dict(doc)
        assert fw.default is Verdict.DENY
        assert fw.conn_ttl == 60
        assert len(fw.rules) == 2
        assert fw.evaluate(mkpkt(protocol=PROTO_UDP, dst_port=53, flags=0)).rule == "dns"

    def test_stats_tracks_counts(self):
        fw = Firewall(rules=[Rule(name="https", action=Verdict.ALLOW, dst_port=443)])
        fw.evaluate(mkpkt(dst_port=443))
        fw.evaluate(mkpkt(dst_port=22))  # default deny
        s = fw.stats()
        assert s["allow"] >= 1
        assert s["deny"] >= 1


# ---------------------------------------------------------------------------
# Stateful tracking
# ---------------------------------------------------------------------------


class TestStatefulTracking:
    def _fw(self, ttl=120.0):
        return Firewall(
            rules=[Rule(name="https", action=Verdict.ALLOW, protocol="TCP", dst_port=443)],
            default=Verdict.DENY,
            conn_ttl=ttl,
        )

    def test_reply_traffic_is_allowed(self):
        fw = self._fw()
        # Client → server outbound: matches rule, gets tracked.
        out = fw.evaluate(mkpkt(src_ip="10.0.0.1", dst_ip="1.1.1.1",
                                src_port=40000, dst_port=443))
        assert out.verdict is Verdict.ALLOW
        assert out.rule == "https"
        # Server → client reply: reversed 5-tuple has no matching rule,
        # but the conn table should allow it.
        reply = fw.evaluate(mkpkt(src_ip="1.1.1.1", dst_ip="10.0.0.1",
                                  src_port=443, dst_port=40000,
                                  flags=TCP_SYN | TCP_ACK))
        assert reply.verdict is Verdict.ALLOW
        assert reply.rule == "established"

    def test_unrelated_traffic_still_denied(self):
        fw = self._fw()
        fw.evaluate(mkpkt(dst_port=443))  # establish a flow
        unrelated = fw.evaluate(mkpkt(src_ip="9.9.9.9", dst_ip="8.8.8.8",
                                      src_port=22, dst_port=22, flags=TCP_SYN))
        assert unrelated.verdict is Verdict.DENY

    def test_ttl_expiry(self):
        fw = self._fw(ttl=1.0)
        t0 = 1_000_000.0
        fw.evaluate(mkpkt(src_ip="10.0.0.1", dst_ip="1.1.1.1",
                          src_port=40000, dst_port=443, ts=t0))
        assert fw.active_connections == 1
        # After TTL elapses, the next evaluate() expires the entry inline.
        fw.evaluate(mkpkt(src_ip="9.9.9.9", dst_ip="8.8.8.8",
                          src_port=80, dst_port=80, ts=t0 + 5.0))
        assert fw.active_connections == 0


# ---------------------------------------------------------------------------
# Anomaly detectors
# ---------------------------------------------------------------------------


class TestPortScanDetector:
    def test_fires_above_threshold(self):
        det = PortScanDetector(window=10.0, threshold=10, cooldown=0.0)
        t = 1000.0
        fired = None
        for port in range(20):
            fired = det.observe(mkpkt(src_ip="3.3.3.3", dst_port=port, ts=t))
        assert fired is not None
        assert fired.kind == "port_scan"
        assert fired.src_ip == "3.3.3.3"

    def test_silent_below_threshold(self):
        det = PortScanDetector(window=10.0, threshold=20, cooldown=0.0)
        for port in range(5):
            assert det.observe(mkpkt(src_ip="3.3.3.3", dst_port=port, ts=1000.0)) is None

    def test_window_evicts_old_events(self):
        det = PortScanDetector(window=2.0, threshold=5, cooldown=0.0)
        for port in range(4):
            det.observe(mkpkt(src_ip="3.3.3.3", dst_port=port, ts=1000.0))
        # Long pause — old events should age out.
        assert det.observe(mkpkt(src_ip="3.3.3.3", dst_port=99, ts=1100.0)) is None


class TestSynFloodDetector:
    def test_fires_on_burst(self):
        det = SynFloodDetector(window=5.0, threshold=50, cooldown=0.0)
        fired = None
        for _ in range(60):
            fired = det.observe(mkpkt(src_ip="4.4.4.4", dst_ip="5.5.5.5",
                                      flags=TCP_SYN, ts=1000.0))
        assert fired is not None
        assert fired.kind == "syn_flood"

    def test_ignores_non_syn(self):
        det = SynFloodDetector(window=5.0, threshold=2, cooldown=0.0)
        for _ in range(10):
            # SYN+ACK is not a raw SYN
            res = det.observe(mkpkt(flags=TCP_SYN | TCP_ACK, ts=1000.0))
            assert res is None


class TestAnomalyFacade:
    def test_fans_out_to_subscribers(self):
        det = AnomalyDetector(
            port_scan=PortScanDetector(window=10.0, threshold=3, cooldown=0.0),
        )
        captured = []
        det.subscribe(captured.append)
        for port in range(10):
            det.observe(mkpkt(src_ip="7.7.7.7", dst_port=port, ts=1000.0))
        assert any(a.kind == "port_scan" for a in captured)
        assert det.alert_count >= 1
