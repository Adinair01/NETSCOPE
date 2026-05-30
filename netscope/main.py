"""NetScope entrypoint.

Wires the sniffer, firewall, anomaly detector, and dashboard into one process.
The CLI is intentionally minimal — everything interesting belongs in the
modules; this file is just the glue.

Usage
-----
    sudo python -m netscope.main --iface en0 --rules rules/rules.yaml
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from netscope.anomaly import AnomalyDetector
from netscope.dashboard import Dashboard
from netscope.firewall import Firewall, Verdict
from netscope.sniffer import Sniffer


log = logging.getLogger("netscope")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="netscope", description="Packet analyzer + stateful firewall + anomaly detector")
    p.add_argument("--iface", default=None, help="Network interface to capture on (default: Scapy picks)")
    p.add_argument("--bpf", default=None, help="Optional BPF filter (e.g. 'tcp or udp')")
    p.add_argument("--rules", default="rules/rules.yaml", help="Path to YAML rules file")
    p.add_argument("--no-dashboard", action="store_true", help="Disable the web dashboard")
    p.add_argument("--host", default="127.0.0.1", help="Dashboard host")
    p.add_argument("--port", type=int, default=8080, help="Dashboard port")
    p.add_argument("--count", type=int, default=0, help="Packet count (0 = unlimited)")
    p.add_argument("--verbose", "-v", action="store_true")
    return p.parse_args(argv)


def _packet_event(decision) -> dict:
    pkt = decision.pkt
    src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_port else pkt.src_ip
    dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_port else pkt.dst_ip
    return {
        "type": "packet",
        "ts": pkt.ts,
        "verdict": decision.verdict.value,
        "rule": decision.rule or "-",
        "proto": pkt.protocol,
        "src": src,
        "dst": dst,
        "flags": pkt.flag_str(),
        "len": pkt.length,
    }


def _alert_event(alert) -> dict:
    return {
        "type": "alert",
        "ts": alert.ts,
        "kind": alert.kind,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "detail": alert.detail,
    }


def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    rules_path = Path(args.rules)
    if not rules_path.exists():
        log.error("rules file not found: %s", rules_path)
        return 2
    firewall = Firewall.from_yaml(rules_path)
    log.info("loaded %d rules from %s (default %s, ttl %.0fs)",
             len(firewall.rules), rules_path, firewall.default.value, firewall.conn_ttl)

    anomaly = AnomalyDetector()

    dashboard: Dashboard | None = None
    if not args.no_dashboard:
        dashboard = Dashboard(host=args.host, port=args.port)
        dashboard.bind_stats(firewall)
        dashboard.start_in_thread()
        log.info("dashboard at http://%s:%d", args.host, args.port)
        anomaly.subscribe(lambda a: dashboard.push_event(_alert_event(a)))

    sniffer = Sniffer(iface=args.iface, bpf=args.bpf, count=args.count)

    def on_packet(pkt):
        decision = firewall.evaluate(pkt)
        if decision.verdict is Verdict.DENY:
            log.debug("DENY %s %s -> %s rule=%s", pkt.protocol, pkt.src_ip, pkt.dst_ip, decision.rule)
        if dashboard is not None:
            dashboard.push_event(_packet_event(decision))
        anomaly.observe(pkt)

    sniffer.subscribe(on_packet)
    log.info("capture starting on iface=%s bpf=%s", args.iface or "<default>", args.bpf or "<none>")
    try:
        sniffer.run()
    except KeyboardInterrupt:
        log.info("stopped by user")
    except PermissionError:
        log.error("permission denied: raw sockets require root / CAP_NET_RAW")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
