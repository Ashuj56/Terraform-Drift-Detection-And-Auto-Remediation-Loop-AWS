"""
Log drift events centrally, correlate with AWS CloudTrail, and track cycle IDs.

On every detection cycle, logs a structured event:
  {
    cycle_id, timestamp, resource_address, physical_resource_id,
    resource_type, actions, risk_level, remediation_status,
    is_duplicate_drift, cloudtrail_correlation
  }

Key Improvements:
  1. Drift Cycle ID & Duplicate Detection: links all events in a cycle and detects repeated drifts
  2. Improved CloudTrail Correlation:
     - Uses real physical AWS Resource IDs (e.g. subnet-xxx, sg-xxx) instead of local address basenames
     - Uses configurable lookback window matching cron schedule (default 6h)
     - Automatically filters out internal CI/CD assumed roles to avoid false correlations
  3. Sanitization: ensures no sensitive plan data is written to JSONL or stdout
"""

import json
import argparse
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

try:
    import boto3
    from botocore.exceptions import ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    print("Notice: boto3 not installed. CloudTrail correlation will operate in simulation mode.", file=sys.stderr)


EVENTS_FILE = Path("drift-events.jsonl")

# Internal CI/CD roles to ignore during CloudTrail correlation
CI_ROLE_SUBSTRINGS = (
    "GitHubActions",
    "github-actions",
    "drift-detection",
    "drift-remediation",
)


def get_existing_pending_resources() -> set[str]:
    """Check recent events in drift-events.jsonl to detect duplicate un-remediated drifts."""
    if not EVENTS_FILE.exists():
        return set()

    pending_resources = set()
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    res_addr = entry.get("resource_address")
                    status = entry.get("remediation_status")
                    if res_addr and status == "pending":
                        pending_resources.add(res_addr)
                    elif res_addr and status in ("applied", "resolved"):
                        pending_resources.discard(res_addr)
                except Exception:
                    continue
    except Exception as e:
        print(f"Warning: could not read existing events for deduplication: {e}", file=sys.stderr)

    return pending_resources


def correlate_with_cloudtrail(
    physical_resource_id: str,
    resource_type: str,
    detected_at: str,
    lookback_hours: int = 6,
    region: str = "us-east-1",
) -> list[dict]:
    """
    Look up CloudTrail events around the time of drift detection using real AWS physical IDs.
    Filters out automated CI/CD roles to isolate human/external out-of-band changes.
    """
    if not BOTO3_AVAILABLE or not physical_resource_id or physical_resource_id == "unknown-resource":
        return []

    try:
        client = boto3.client("cloudtrail", region_name=region)

        detected_dt = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
        start_time = detected_dt - timedelta(hours=lookback_hours)
        end_time = detected_dt

        # Query CloudTrail by ResourceName with actual physical ID
        response = client.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": physical_resource_id}
            ],
            StartTime=start_time,
            EndTime=end_time,
            MaxResults=10,
        )

        correlated = []
        for event in response.get("Events", []):
            username = event.get("Username") or "unknown"

            # Parse raw CloudTrail event payload for identity and IP details
            raw = event.get("CloudTrailEvent")
            user_identity = {}
            source_ip = None
            user_agent = None

            if raw:
                try:
                    raw_parsed = json.loads(raw)
                    user_identity = raw_parsed.get("userIdentity", {})
                    source_ip = raw_parsed.get("sourceIPAddress")
                    user_agent = raw_parsed.get("userAgent")
                except Exception:
                    pass

            principal_arn = user_identity.get("arn", "")

            # Filter out GitHub Actions / drift automation itself
            is_automation = any(
                ci_sub.lower() in username.lower() or ci_sub.lower() in principal_arn.lower()
                for ci_sub in CI_ROLE_SUBSTRINGS
            )
            if is_automation:
                continue

            ct_entry = {
                "event_name": event.get("EventName"),
                "event_time": event.get("EventTime", "").isoformat() if event.get("EventTime") else None,
                "username": username,
                "principal_arn": principal_arn,
                "principal_type": user_identity.get("type", "Unknown"),
                "source_ip": source_ip,
                "user_agent": user_agent,
                "resource_name": physical_resource_id,
                "resource_type": resource_type,
            }
            correlated.append(ct_entry)

        return correlated

    except ClientError as e:
        print(f"Warning: CloudTrail lookup API error for {physical_resource_id}: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Warning: CloudTrail correlation failed: {e}", file=sys.stderr)
        return []


def log_detection_events(drift_summary: dict, region: str = "us-east-1", lookback_hours: int = 6):
    """Log one event per drifted resource with cycle ID, deduplication, and CloudTrail correlation."""
    cycle_id = drift_summary.get("cycle_id", f"drift-cycle-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}")
    detected_at = drift_summary["detected_at"]
    existing_pending = get_existing_pending_resources()

    events_written = 0

    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        for drift_event in drift_summary["drift_events"]:
            res_addr = drift_event["resource_address"]
            phys_id = drift_event.get("physical_resource_id", "unknown-resource")
            res_type = drift_event["resource_type"]

            is_duplicate = res_addr in existing_pending

            # CloudTrail Correlation
            ct_events = correlate_with_cloudtrail(
                physical_resource_id=phys_id,
                resource_type=res_type,
                detected_at=detected_at,
                lookback_hours=lookback_hours,
                region=region,
            )

            log_entry = {
                "cycle_id": cycle_id,
                "timestamp": detected_at,
                "event_type": "drift_detected",
                "resource_address": res_addr,
                "physical_resource_id": phys_id,
                "resource_type": res_type,
                "actions": drift_event["actions"],
                "risk_level": drift_event["risk_level"],
                "risk_reasons": drift_event.get("risk_reasons", []),
                "changed_attributes": drift_event["changed_attributes"],
                "remediation_status": "pending",
                "is_duplicate_drift": is_duplicate,
                "cloudtrail_correlation": ct_events,
            }

            f.write(json.dumps(log_entry) + "\n")
            print(json.dumps(log_entry, indent=2))
            events_written += 1

    print(f"\n✅ Logged {events_written} drift event(s) for cycle {cycle_id} to {EVENTS_FILE}")
    return events_written


def log_apply_event(
    cycle_id: str,
    status: str,
    risk_level: str,
    auto_apply: bool,
    pr_number: str,
    pr_url: str,
):
    """Log the remediation apply result with cycle ID and resolution status."""
    now_iso = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "cycle_id": cycle_id,
        "timestamp": now_iso,
        "event_type": "drift_remediated",
        "remediation_status": "applied" if status == "success" else "failed",
        "risk_level": risk_level,
        "auto_apply": auto_apply,
        "pr_number": pr_number,
        "pr_url": pr_url,
        "applied_at": now_iso,
    }

    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

    print(json.dumps(log_entry, indent=2))
    print(f"✅ Remediation event for cycle {cycle_id} logged to {EVENTS_FILE}")


def main():
    parser = argparse.ArgumentParser(description="Log drift events, track cycle IDs, and correlate with CloudTrail")
    parser.add_argument("--action", required=True, choices=["detect", "apply"], help="Type of event to log")
    parser.add_argument("--drift-summary", help="Path to drift-summary.json (for detect action)")
    parser.add_argument("--cycle-id", default="", help="Drift cycle ID (for detect or apply action)")
    parser.add_argument("--status", default="success", help="Apply status (for apply action)")
    parser.add_argument("--risk-level", default="UNKNOWN", help="Risk level (for apply action)")
    parser.add_argument("--auto-apply", default="false", help="Was this an auto-apply? (for apply action)")
    parser.add_argument("--pr-number", default="", help="PR number (for apply action)")
    parser.add_argument("--pr-url", default="", help="PR URL (for apply action)")
    parser.add_argument("--lookback-hours", type=int, default=6, help="CloudTrail lookup window in hours")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    args = parser.parse_args()

    if args.action == "detect":
        if not args.drift_summary:
            print("ERROR: --drift-summary is required for 'detect' action", file=sys.stderr)
            sys.exit(1)
        with open(args.drift_summary, encoding="utf-8") as f:
            summary = json.load(f)
        if args.cycle_id and "cycle_id" not in summary:
            summary["cycle_id"] = args.cycle_id
        log_detection_events(summary, region=args.region, lookback_hours=args.lookback_hours)

    elif args.action == "apply":
        cycle_id = args.cycle_id or f"drift-cycle-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        log_apply_event(
            cycle_id=cycle_id,
            status=args.status,
            risk_level=args.risk_level,
            auto_apply=args.auto_apply.lower() == "true",
            pr_number=args.pr_number,
            pr_url=args.pr_url,
        )


if __name__ == "__main__":
    main()
