"""
Parse Terraform plan JSON output into a structured drift summary.

Reads `plan.json` produced by `terraform show -json plan.tfplan`,
extracts resource-level changes, and classifies each by risk tier:
  - LOW_RISK:  tags, labels, descriptions on known manageable resources — safe for auto-apply
  - HIGH_RISK: VPC, security groups, IAM roles/policies, deletions, replacements, unknown resources — require manual approval

Safety Guarantees:
  1. Any deletion or replacement action is strictly HIGH_RISK (auto-apply blocked).
  2. Unknown / unrecognized resource types are strictly HIGH_RISK.
  3. Sensitive attribute values are automatically masked and sanitized.
  4. Each detection run is tagged with a unique drift-cycle ID.
  5. Physical AWS resource IDs are extracted for CloudTrail correlation.

Outputs:
  - drift-summary.json  (sanitized, machine-readable for PR creation and logging)
  - GitHub Actions step outputs (risk_level, resource_count, auto_apply, cycle_id)
"""

import json
import argparse
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

# ── Risk Classification Rules ─────────────────────────────────────────────────

# Resource types that are explicitly high-risk (network, security, compute core, IAM)
HIGH_RISK_RESOURCE_TYPES = {
    "aws_vpc",
    "aws_subnet",
    "aws_internet_gateway",
    "aws_nat_gateway",
    "aws_route_table",
    "aws_route_table_association",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_network_acl",
    "aws_iam_role",
    "aws_iam_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user",
    "aws_iam_group",
    "aws_iam_openid_connect_provider",
    "aws_eks_cluster",
    "aws_eks_node_group",
    "aws_kms_key",
    "aws_kms_alias",
}

# Catalog of known resource types. Any resource NOT in this set is treated as UNKNOWN -> HIGH_RISK
KNOWN_CATALOG_RESOURCE_TYPES = HIGH_RISK_RESOURCE_TYPES | {
    "aws_s3_bucket",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_versioning",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_instance",
    "aws_ebs_volume",
    "aws_cloudwatch_log_group",
    "aws_cloudwatch_metric_alarm",
    "aws_sqs_queue",
    "aws_sns_topic",
    "aws_ecr_repository",
}

# Attributes that are considered low-risk when modified on low-risk resources
LOW_RISK_ATTRIBUTES = {
    "tags",
    "tags_all",
    "description",
}

# Substrings in attribute names that indicate sensitive data
SENSITIVE_KEY_PATTERNS = (
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "private",
    "cert",
    "auth",
    "api_key",
    "access_key",
    "secret_key",
    "bearer",
)


def is_sensitive_attribute(key: str, before_sensitive: dict | None, after_sensitive: dict | None) -> bool:
    """Check if an attribute is marked sensitive by Terraform or matches sensitive patterns."""
    key_lower = key.lower()
    for pattern in SENSITIVE_KEY_PATTERNS:
        if pattern in key_lower:
            return True

    def check_sensitive_dict(d: dict | None, k: str) -> bool:
        if not d or not isinstance(d, dict):
            return False
        val = d.get(k)
        if isinstance(val, bool) and val:
            return True
        if isinstance(val, dict) and any(val.values()):
            return True
        return False

    if check_sensitive_dict(before_sensitive, key):
        return True
    if check_sensitive_dict(after_sensitive, key):
        return True

    return False


def classify_resource_risk(
    resource_type: str,
    actions: list[str],
    changed_attributes: list[str],
) -> tuple[str, list[str]]:
    """
    Classify risk tier for a resource change and return (risk_level, risk_reasons).

    Rules:
      1. Any deletion or replacement -> HIGH_RISK (destructive change protection)
      2. Unknown / unrecognized resource type -> HIGH_RISK
      3. Resource type in HIGH_RISK_RESOURCE_TYPES -> HIGH_RISK
      4. Any changed attribute not in LOW_RISK_ATTRIBUTES -> HIGH_RISK
      5. Otherwise -> LOW_RISK
    """
    reasons = []

    # Rule 1: Block deletion and replacement auto-apply
    actions_set = set(actions)
    if "delete" in actions_set:
        reasons.append("destructive_action: deletion requested")
    if {"create", "delete"}.issubset(actions_set) or {"delete", "create"}.issubset(actions_set):
        reasons.append("destructive_action: resource replacement requested")

    # Rule 2: Make unknown resources high-risk
    if not resource_type or resource_type == "unknown":
        reasons.append("unknown_resource: resource type is undefined or unknown")
    elif resource_type not in KNOWN_CATALOG_RESOURCE_TYPES:
        reasons.append(f"unknown_resource: '{resource_type}' is not in known managed catalog")

    # Rule 3: High-risk resource type
    if resource_type in HIGH_RISK_RESOURCE_TYPES:
        reasons.append(f"critical_resource_type: '{resource_type}' requires mandatory human approval")

    # Rule 4: Non-trivial attribute changes
    non_trivial = [a for a in changed_attributes if a not in LOW_RISK_ATTRIBUTES]
    if non_trivial:
        reasons.append(f"non_trivial_attributes: {', '.join(non_trivial)}")

    if reasons:
        return "HIGH_RISK", reasons

    return "LOW_RISK", ["low_risk_attributes_only: tags/metadata modification on managed resource"]


def sanitize_value(val: any) -> any:
    """Recursively redact sensitive strings or keys in values."""
    if isinstance(val, dict):
        sanitized = {}
        for k, v in val.items():
            if any(p in k.lower() for p in SENSITIVE_KEY_PATTERNS):
                sanitized[k] = "***SENSITIVE***"
            else:
                sanitized[k] = sanitize_value(v)
        return sanitized
    if isinstance(val, list):
        return [sanitize_value(v) for v in val]
    return val


def extract_attribute_diffs(
    before: dict | None,
    after: dict | None,
    before_sensitive: dict | None,
    after_sensitive: dict | None,
) -> list[dict]:
    """Compare before/after attribute values, masking all sensitive values."""
    diffs = []
    if not before and not after:
        return diffs

    all_keys = set()
    if before:
        all_keys.update(before.keys())
    if after:
        all_keys.update(after.keys())

    for key in sorted(all_keys):
        before_val = before.get(key) if before else None
        after_val = after.get(key) if after else None

        # Skip unchanged attributes
        if before_val == after_val:
            continue

        # Mask sensitive attributes
        if is_sensitive_attribute(key, before_sensitive, after_sensitive):
            masked_before = "***SENSITIVE***" if before_val is not None else None
            masked_after = "***SENSITIVE***" if after_val is not None else None
        else:
            masked_before = sanitize_value(before_val)
            masked_after = sanitize_value(after_val)

        diffs.append({
            "attribute": key,
            "before": masked_before,
            "after": masked_after,
        })

    return diffs


def extract_physical_id(change: dict) -> str:
    """Extract physical AWS resource identifier (e.g. subnet-xxx, sg-xxx, arn) from change data."""
    before = change.get("change", {}).get("before") or {}
    after = change.get("change", {}).get("after") or {}

    for source in (before, after):
        if isinstance(source, dict):
            # Check id
            if source.get("id"):
                return str(source["id"])
            # Check arn
            if source.get("arn"):
                return str(source["arn"])
            # Check name / cluster_name / vpc_id
            for name_field in ("cluster_name", "role_name", "group_name", "vpc_id", "name"):
                if source.get(name_field):
                    return str(source[name_field])

    # Fallback to address basename
    addr = change.get("address", "")
    return addr.split(".")[-1] if addr else "unknown-resource"


def parse_plan(plan_json_path: str, cycle_id: str | None = None) -> dict:
    """Parse a Terraform plan JSON file and return a structured drift summary."""
    with open(plan_json_path, "r", encoding="utf-8") as f:
        plan = json.load(f)

    if not cycle_id:
        cycle_id = f"drift-cycle-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    resource_changes = plan.get("resource_changes", [])
    drift_events = []
    has_destructive_changes = False

    for change in resource_changes:
        actions = change.get("change", {}).get("actions", ["no-op"])

        # Skip no-op resources (no drift on these)
        if actions == ["no-op"] or actions == ["read"]:
            continue

        resource_type = change.get("type", "unknown")
        resource_address = change.get("address", "unknown")
        module = change.get("module_address", "root")

        before = change.get("change", {}).get("before")
        after = change.get("change", {}).get("after")
        before_sensitive = change.get("change", {}).get("before_sensitive")
        after_sensitive = change.get("change", {}).get("after_sensitive")

        attribute_diffs = extract_attribute_diffs(before, after, before_sensitive, after_sensitive)
        changed_attributes = [d["attribute"] for d in attribute_diffs]

        risk_level, risk_reasons = classify_resource_risk(resource_type, actions, changed_attributes)
        physical_id = extract_physical_id(change)

        if "delete" in set(actions):
            has_destructive_changes = True

        drift_events.append({
            "resource_address": resource_address,
            "resource_type": resource_type,
            "physical_resource_id": physical_id,
            "module": module,
            "actions": actions,
            "risk_level": risk_level,
            "risk_reasons": risk_reasons,
            "changed_attributes": changed_attributes,
            "attribute_diffs": attribute_diffs,
        })

    # Determine overall risk
    overall_risk = "HIGH_RISK" if any(e["risk_level"] == "HIGH_RISK" for e in drift_events) else (
        "LOW_RISK" if drift_events else "NO_DRIFT"
    )

    # Auto-apply is strictly forbidden if high risk or destructive changes exist
    auto_apply = (overall_risk == "LOW_RISK") and not has_destructive_changes

    summary = {
        "cycle_id": cycle_id,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "overall_risk": overall_risk,
        "auto_apply": auto_apply,
        "has_destructive_changes": has_destructive_changes,
        "resource_count": len(drift_events),
        "high_risk_count": sum(1 for e in drift_events if e["risk_level"] == "HIGH_RISK"),
        "low_risk_count": sum(1 for e in drift_events if e["risk_level"] == "LOW_RISK"),
        "drift_events": drift_events,
    }

    return summary


def write_github_output(summary: dict, github_output_path: str):
    """Write step outputs for GitHub Actions to consume."""
    with open(github_output_path, "a", encoding="utf-8") as f:
        f.write(f"cycle_id={summary['cycle_id']}\n")
        f.write(f"risk_level={summary['overall_risk']}\n")
        f.write(f"resource_count={summary['resource_count']}\n")
        f.write(f"high_risk_count={summary['high_risk_count']}\n")
        f.write(f"low_risk_count={summary['low_risk_count']}\n")
        f.write(f"auto_apply={str(summary['auto_apply']).lower()}\n")
        f.write(f"has_destructive_changes={str(summary['has_destructive_changes']).lower()}\n")


def main():
    parser = argparse.ArgumentParser(description="Parse Terraform plan JSON for drift")
    parser.add_argument("--plan-json", required=True, help="Path to plan.json")
    parser.add_argument("--output-file", required=True, help="Path to write drift-summary.json")
    parser.add_argument("--cycle-id", help="Optional explicit drift cycle ID")
    parser.add_argument("--github-output", help="Path to $GITHUB_OUTPUT file for step outputs")
    args = parser.parse_args()

    print(f"Parsing plan: {args.plan_json}")

    if not Path(args.plan_json).exists():
        print(f"ERROR: Plan file not found: {args.plan_json}", file=sys.stderr)
        sys.exit(1)

    summary = parse_plan(args.plan_json, cycle_id=args.cycle_id)

    # Write structured output (guaranteed sanitized)
    with open(args.output_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n=== Drift Summary ===")
    print(f"Cycle ID:      {summary['cycle_id']}")
    print(f"Detected at:   {summary['detected_at']}")
    print(f"Total changes: {summary['resource_count']}")
    print(f"High-risk:     {summary['high_risk_count']}")
    print(f"Low-risk:      {summary['low_risk_count']}")
    print(f"Overall risk:  {summary['overall_risk']}")
    print(f"Auto-apply:    {summary['auto_apply']}")
    print(f"Destructive:   {summary['has_destructive_changes']}")
    print(f"\nDrift events:")

    for event in summary["drift_events"]:
        icon = "🔴" if event["risk_level"] == "HIGH_RISK" else "🟡"
        print(f"  {icon} {event['resource_address']} ({', '.join(event['actions'])}) -> Physical ID: {event['physical_resource_id']}")
        if event["risk_reasons"]:
            print(f"     Reasons: {'; '.join(event['risk_reasons'])}")
        for diff in event["attribute_diffs"]:
            print(f"     {diff['attribute']}: {diff['before']!r} → {diff['after']!r}")

    if args.github_output:
        write_github_output(summary, args.github_output)
        print(f"\nGitHub step outputs written to: {args.github_output}")

    print(f"\nDrift summary written to: {args.output_file}")


if __name__ == "__main__":
    main()
