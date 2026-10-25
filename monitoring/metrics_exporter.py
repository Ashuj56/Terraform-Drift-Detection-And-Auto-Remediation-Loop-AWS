#!/usr/bin/env python3
"""
Prometheus metrics exporter for drift events.

Reads drift-events.jsonl and exposes metrics on :8000/metrics for Prometheus to scrape.

Metrics exposed:
  drift_events_total{risk_level, resource_type, status}  — counter
  drift_pending_total                                      — gauge
  drift_mttr_seconds                                      — histogram (mean time to remediate)
  drift_last_detected_timestamp                            — gauge (Unix epoch of last detection)

Run: python monitoring/metrics_exporter.py --events-file drift-events.jsonl
"""

import json
import time
import argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler


def load_events(events_file: str) -> list[dict]:
    """Load all drift events from JSONL file."""
    path = Path(events_file)
    if not path.exists():
        return []
    events = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def compute_mttr(events: list[dict]) -> list[float]:
    """
    Compute mean time to remediate for each detection→apply pair.
    Pairs events by resource_address: drift_detected → drift_remediated.
    Returns list of MTTR values in seconds.
    """
    detections = {}  # resource_address → detected timestamp
    mttrs = []

    for e in sorted(events, key=lambda x: x.get("timestamp", "")):
        if e.get("event_type") == "drift_detected":
            addr = e.get("resource_address", "unknown")
            detections[addr] = e["timestamp"]
        elif e.get("event_type") == "drift_remediated":
            # Match to any pending detection (simplified: use earliest)
            applied_at = e.get("applied_at") or e.get("timestamp")
            for addr, detected_ts in list(detections.items()):
                try:
                    d = datetime.fromisoformat(detected_ts.replace("Z", "+00:00"))
                    a = datetime.fromisoformat(applied_at.replace("Z", "+00:00"))
                    mttrs.append((a - d).total_seconds())
                    del detections[addr]
                    break
                except Exception:
                    pass

    return mttrs


def generate_prometheus_metrics(events_file: str) -> str:
    """Generate Prometheus-format metrics text."""
    events = load_events(events_file)

    # ── Counters ────────────────────────────────────────────────────────────
    events_by_label = defaultdict(int)
    pending_count = 0
    last_detected_ts = 0.0

    for e in events:
        if e.get("event_type") == "drift_detected":
            risk = e.get("risk_level", "UNKNOWN")
            rtype = e.get("resource_type", "unknown")
            status = e.get("remediation_status", "pending")
            events_by_label[(risk, rtype, status)] += 1

            if status == "pending":
                pending_count += 1

            try:
                ts = datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00"))
                ts_epoch = ts.timestamp()
                if ts_epoch > last_detected_ts:
                    last_detected_ts = ts_epoch
            except Exception:
                pass

    # ── MTTR ────────────────────────────────────────────────────────────────
    mttrs = compute_mttr(events)
    avg_mttr = sum(mttrs) / len(mttrs) if mttrs else 0.0

    lines = []

    # drift_events_total
    lines.append("# HELP drift_events_total Total number of drift detection events")
    lines.append("# TYPE drift_events_total counter")
    for (risk, rtype, status), count in events_by_label.items():
        lines.append(
            f'drift_events_total{{risk_level="{risk}",resource_type="{rtype}",status="{status}"}} {count}'
        )

    # drift_pending_total
    lines.append("")
    lines.append("# HELP drift_pending_total Number of drift events pending remediation")
    lines.append("# TYPE drift_pending_total gauge")
    lines.append(f"drift_pending_total {pending_count}")

    # drift_mttr_seconds_avg
    lines.append("")
    lines.append("# HELP drift_mttr_seconds_avg Average mean time to remediate drift (seconds)")
    lines.append("# TYPE drift_mttr_seconds_avg gauge")
    lines.append(f"drift_mttr_seconds_avg {avg_mttr:.2f}")

    # drift_last_detected_timestamp
    lines.append("")
    lines.append("# HELP drift_last_detected_timestamp Unix timestamp of the most recent drift detection")
    lines.append("# TYPE drift_last_detected_timestamp gauge")
    lines.append(f"drift_last_detected_timestamp {last_detected_ts:.0f}")

    # drift_total_remediations
    remediations = sum(1 for e in events if e.get("event_type") == "drift_remediated")
    auto_applied = sum(
        1 for e in events
        if e.get("event_type") == "drift_remediated" and e.get("auto_apply") is True
    )
    lines.append("")
    lines.append("# HELP drift_remediations_total Total number of drift remediations applied")
    lines.append("# TYPE drift_remediations_total counter")
    lines.append(f'drift_remediations_total{{mode="auto"}} {auto_applied}')
    lines.append(f'drift_remediations_total{{mode="manual"}} {remediations - auto_applied}')

    return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def __init__(self, events_file, *args, **kwargs):
        self.events_file = events_file
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == "/metrics":
            metrics = generate_prometheus_metrics(self.events_file)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            self.wfile.write(metrics.encode("utf-8"))
        elif self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default HTTP request logs


def main():
    parser = argparse.ArgumentParser(description="Prometheus metrics exporter for drift events")
    parser.add_argument("--events-file", default="drift-events.jsonl", help="Path to drift events JSONL file")
    parser.add_argument("--port", type=int, default=8000, help="Port to serve metrics on")
    args = parser.parse_args()

    print(f"Starting metrics exporter on :{args.port}/metrics")
    print(f"Reading events from: {args.events_file}")

    import functools
    handler = functools.partial(MetricsHandler, args.events_file)
    server = HTTPServer(("0.0.0.0", args.port), handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down metrics exporter")
        server.shutdown()


if __name__ == "__main__":
    main()
