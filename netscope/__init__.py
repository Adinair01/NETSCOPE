"""NetScope — packet analyzer, stateful firewall, and anomaly detector."""

__version__ = "0.1.0"

from netscope.sniffer import Packet, Sniffer
from netscope.firewall import Firewall, Rule, Verdict
from netscope.anomaly import AnomalyDetector, Alert

__all__ = [
    "Packet",
    "Sniffer",
    "Firewall",
    "Rule",
    "Verdict",
    "AnomalyDetector",
    "Alert",
]
