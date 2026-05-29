"""Live web dashboard built on Flask + Server-Sent Events.

The dashboard is intentionally tiny: a bounded ring buffer of events, a stats
endpoint, and an SSE stream that fans the ring out to any number of browsers.
Producers (sniffer, firewall, anomaly detector) push events in via
`push_event`. The dashboard never blocks them — full buffers drop the oldest
event, not the newest.
"""

from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Optional

from flask import Flask, Response, jsonify, render_template_string


_INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetScope</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; margin: 0; background: #0d1117; color: #c9d1d9; }
  header { padding: 12px 20px; background: #161b22; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }
  h1 { font-size: 16px; margin: 0; }
  .stats { display: flex; gap: 18px; font-size: 13px; }
  .stat b { color: #58a6ff; }
  main { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; padding: 16px; }
  section { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; }
  h2 { font-size: 13px; margin: 0 0 8px; color: #8b949e; text-transform: uppercase; letter-spacing: .08em; }
  pre { margin: 0; max-height: 70vh; overflow: auto; font-size: 12px; line-height: 1.45; }
  .allow { color: #3fb950; }
  .deny { color: #f85149; }
  .alert { color: #d29922; }
  .row { padding: 2px 0; border-bottom: 1px solid #21262d; }
</style>
</head>
<body>
<header>
  <h1>NetScope — live capture</h1>
  <div class="stats">
    <div class="stat">allow <b id="s-allow">0</b></div>
    <div class="stat">deny <b id="s-deny">0</b></div>
    <div class="stat">established <b id="s-est">0</b></div>
    <div class="stat">conns <b id="s-conns">0</b></div>
    <div class="stat">alerts <b id="s-alerts">0</b></div>
  </div>
</header>
<main>
  <section>
    <h2>Packets</h2>
    <pre id="packets"></pre>
  </section>
  <section>
    <h2>Alerts</h2>
    <pre id="alerts"></pre>
  </section>
</main>
<script>
const pkts = document.getElementById('packets');
const alerts = document.getElementById('alerts');
const MAX_ROWS = 400;

function append(el, html) {
  const row = document.createElement('div');
  row.className = 'row';
  row.innerHTML = html;
  el.prepend(row);
  while (el.childElementCount > MAX_ROWS) el.removeChild(el.lastChild);
}

const es = new EventSource('/events');
es.onmessage = (e) => {
  const ev = JSON.parse(e.data);
  if (ev.type === 'packet') {
    const v = ev.verdict.toLowerCase();
    append(pkts, `<span class="${v}">${ev.verdict}</span> ${ev.proto} ${ev.src || '?'} → ${ev.dst || '?'} <small>[${ev.rule}]</small>`);
  } else if (ev.type === 'alert') {
    append(alerts, `<span class="alert">${ev.kind.toUpperCase()}</span> ${ev.src_ip} → ${ev.dst_ip || '*'} <small>${ev.detail}</small>`);
  }
};

async function pollStats() {
  try {
    const r = await fetch('/stats');
    const s = await r.json();
    document.getElementById('s-allow').textContent = s.allow ?? 0;
    document.getElementById('s-deny').textContent = s.deny ?? 0;
    document.getElementById('s-est').textContent = s.established ?? 0;
    document.getElementById('s-conns').textContent = s.active_connections ?? 0;
    document.getElementById('s-alerts').textContent = s.alerts ?? 0;
  } catch (e) {}
}
setInterval(pollStats, 1000); pollStats();
</script>
</body>
</html>
"""


@dataclass
class Dashboard:
    """Flask app + event bus. Safe to call push_event() from any thread."""

    host: str = "127.0.0.1"
    port: int = 8080
    buffer_size: int = 2000

    _events: Deque[dict] = field(init=False, repr=False)
    _cond: threading.Condition = field(default_factory=threading.Condition, init=False, repr=False)
    _seq: int = field(default=0, init=False, repr=False)
    _stats_provider: Optional[Any] = field(default=None, init=False, repr=False)
    _alert_count: int = field(default=0, init=False, repr=False)
    app: Flask = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._events = deque(maxlen=self.buffer_size)
        self.app = Flask(__name__)
        self._register_routes()

    # -- producer API -------------------------------------------------------

    def push_event(self, event: dict) -> None:
        """Append an event to the ring and wake any SSE listeners."""
        with self._cond:
            self._seq += 1
            event = dict(event, _seq=self._seq)
            if event.get("type") == "alert":
                self._alert_count += 1
            self._events.append(event)
            self._cond.notify_all()

    def bind_stats(self, provider) -> None:
        """`provider` must expose a stats() -> dict method (e.g. Firewall)."""
        self._stats_provider = provider

    # -- routes -------------------------------------------------------------

    def _register_routes(self) -> None:
        @self.app.route("/")
        def index():
            return render_template_string(_INDEX_HTML)

        @self.app.route("/stats")
        def stats():
            base = {"alerts": self._alert_count}
            if self._stats_provider is not None:
                try:
                    base.update(self._stats_provider.stats())
                except Exception:
                    pass
            return jsonify(base)

        @self.app.route("/events")
        def events():
            return Response(self._stream(), mimetype="text/event-stream")

    def _stream(self):
        last_seq = 0
        # Yield a hello so the browser confirms the stream is alive.
        yield f"data: {json.dumps({'type': 'hello', 'ts': time.time()})}\n\n"
        while True:
            with self._cond:
                while not self._events or self._events[-1]["_seq"] <= last_seq:
                    if not self._cond.wait(timeout=15.0):
                        # heartbeat keeps the connection through proxies
                        yield ": keepalive\n\n"
                        continue
                pending = [e for e in self._events if e["_seq"] > last_seq]
                if pending:
                    last_seq = pending[-1]["_seq"]
            for e in pending:
                yield f"data: {json.dumps(e)}\n\n"

    # -- lifecycle ----------------------------------------------------------

    def run(self) -> None:
        """Run the Flask development server (blocking)."""
        self.app.run(host=self.host, port=self.port, threaded=True, use_reloader=False)

    def start_in_thread(self) -> threading.Thread:
        """Run the server in a daemon thread; returns the thread handle."""
        t = threading.Thread(target=self.run, name="netscope-dashboard", daemon=True)
        t.start()
        return t
