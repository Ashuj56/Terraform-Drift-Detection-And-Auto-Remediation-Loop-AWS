#!/usr/bin/env python3
"""
Auto-create a GitHub Pull Request for drift remediation with duplicate prevention.

Reads drift-summary.json produced by parse_drift.py and creates/updates a PR via
the GitHub REST API with:
  - Drift cycle ID traceability
  - Duplicate detection: if an open drift PR already exists, updates it instead of creating duplicates
  - Formatted diff table (resource | physical ID | attribute | before | after)
  - Risk tier badge, destructive changes warnings, and review routing instructions
  - Labels: 'drift-detection', 'auto-apply' (low-risk) or 'requires-approval' (high-risk)
"""

import json
import argparse
import os
import sys
import requests
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


# ── GitHub API helpers ────────────────────────────────────────────────────────

def clean_token(token: str) -> str:
    """Normalize token by stripping whitespace and redundant prefixes."""
    token = token.strip()
    if token.startswith("Bearer "):
        token = token[7:].strip()
    elif token.startswith("token "):
        token = token[6:].strip()
    return token


def gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {clean_token(token)}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def ensure_label_exists(repo: str, label_name: str, color: str, description: str, token: str):
    """Create a label if it doesn't already exist."""
    url = f"https://api.github.com/repos/{repo}/labels"
    payload = {"name": label_name, "color": color, "description": description}
    try:
        r = requests.post(url, headers=gh_headers(token), json=payload)
        if r.status_code in (200, 201, 422):
            return
        print(f"Warning: could not create label '{label_name}': {r.status_code} {r.text}")
    except Exception as e:
        print(f"Warning: label check error for '{label_name}': {e}")


def find_existing_open_drift_pr(repo: str, token: str) -> dict | None:
    """Search for an existing open drift-fix PR to prevent duplicates."""
    url = f"https://api.github.com/repos/{repo}/pulls"
    params = {"state": "open", "per_page": 30}
    try:
        r = requests.get(url, headers=gh_headers(token), params=params)
        if r.status_code != 200:
            print(f"Warning: could not check open PRs: {r.status_code} {r.text}")
            return None

        for pr in r.json():
            head_ref = pr.get("head", {}).get("ref", "")
            labels = [lbl.get("name") for lbl in pr.get("labels", [])]
            if head_ref.startswith("drift-fix-") or "drift-detection" in labels:
                return pr
    except Exception as e:
        print(f"Warning: failed to query open PRs: {e}")

    return None


def post_pr_comment(repo: str, pr_number: int, comment: str, token: str):
    """Post an update comment to an existing PR."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    try:
        r = requests.post(url, headers=gh_headers(token), json={"body": comment})
        if r.status_code in (200, 201):
            print(f"✅ Comment posted to existing PR #{pr_number}")
        else:
            print(f"Warning: could not post comment: {r.status_code} {r.text}")
    except Exception as e:
        print(f"Warning: failed to post PR comment: {e}")


def build_pr_body(summary: dict, run_id: str) -> str:
    """Build a rich Markdown PR body from the sanitized drift summary."""
    cycle_id = summary.get("cycle_id", "drift-cycle-unknown")
    detected_at = summary["detected_at"]
    overall_risk = summary["overall_risk"]
    resource_count = summary["resource_count"]
    high_risk = summary["high_risk_count"]
    low_risk = summary["low_risk_count"]
    auto_apply = summary["auto_apply"]
    has_destructive = summary.get("has_destructive_changes", False)
    drift_events = summary["drift_events"]

    risk_badge = (
        "🔴 **HIGH RISK — Manual Approval Required**"
        if overall_risk == "HIGH_RISK"
        else "🟡 **LOW RISK — Eligible for Auto-Apply**"
    )

    destructive_warning = ""
    if has_destructive:
        destructive_warning = (
            "> ⛔ **CRITICAL ALERT: Destructive Actions Detected!**\n"
            "> This drift includes resource **deletion or replacement**. Auto-apply has been **strictly disabled**.\n"
            "> Detailed human verification and approval is required before applying.\n\n"
        )

    routing = (
        "> ⚠️ This PR touches high-risk or critical infrastructure (VPC/Security Groups/IAM/EKS/Unknown). "
        "**A designated approver must review and approve before merge.**"
        if overall_risk == "HIGH_RISK"
        else
        "> ✅ All changes are low-risk (tags/metadata on managed resources). "
        "This PR is eligible for **automated merge** after CI validation passes."
    )

    # Build diff table
    table_rows = []
    for event in drift_events:
        phys_id = event.get("physical_resource_id", "N/A")
        risk_icon = "🔴" if event["risk_level"] == "HIGH_RISK" else "🟡"
        for diff in event["attribute_diffs"]:
            before_str = str(diff["before"]) if diff["before"] is not None else "*(none)*"
            after_str = str(diff["after"]) if diff["after"] is not None else "*(none)*"
            table_rows.append(
                f"| `{event['resource_address']}` | `{phys_id}` | `{diff['attribute']}` "
                f"| `{before_str[:70]}` | `{after_str[:70]}` | {risk_icon} {event['risk_level']} |"
            )

    table = "\n".join(table_rows) if table_rows else "| *(no attribute diffs found)* | | | | | |"

    # Build action list
    action_summary = []
    for event in drift_events:
        icon = "🔴" if event["risk_level"] == "HIGH_RISK" else "🟡"
        reasons_text = f" — *{'; '.join(event['risk_reasons'])}*" if event.get("risk_reasons") else ""
        action_summary.append(
            f"- {icon} `{event['resource_address']}` (`{event.get('physical_resource_id', 'N/A')}`) — "
            f"**{', '.join(event['actions'])}** ({event['risk_level']}){reasons_text}"
        )

    action_summary_str = "\n".join(action_summary)
    auto_apply_str = "Yes (Auto-Merge enabled)" if auto_apply else "No (Human Review Required)"
    destructive_str = "Yes ⚠️" if has_destructive else "No"

    what_to_do = (
        "1. **Review** the affected resources and attribute diff table above.\n"
        "2. Check **CloudTrail** below to identify the principal who made the change.\n"
        "3. **Approve & Merge** this PR if the change is expected, or close it and revert live infra."
        if overall_risk == "HIGH_RISK"
        else
        "1. **Review** the diff table above.\n"
        "2. This PR will be **auto-merged** automatically once CI validation finishes."
    )

    first_phys_id = drift_events[0].get("physical_resource_id", "<resource-id>") if drift_events else "<resource-id>"
    start_date = detected_at[:10]

    return f"""## 🔍 Drift Remediation Report

{risk_badge}

{destructive_warning}**Drift Cycle ID:** `{cycle_id}`  
**Detected at:** `{detected_at}`  
**CI Run:** [#{run_id}](https://github.com/${{REPO}}/actions/runs/{run_id})  

{routing}

---

## 📊 Summary

| Metric | Value |
|--------|-------|
| Cycle ID | `{cycle_id}` |
| Total drifted resources | **{resource_count}** |
| High-risk resources | **{high_risk}** |
| Low-risk resources | **{low_risk}** |
| Destructive actions | **{destructive_str}** |
| Overall risk tier | **{overall_risk}** |
| Auto-apply eligible | **{auto_apply_str}** |

---

## 📋 Affected Resources

{action_summary_str}

---

## 🔄 Attribute-Level Diff

| Resource | Physical AWS ID | Attribute | Desired (State) | Live (Drifted) | Risk Tier |
|----------|-----------------|-----------|-----------------|----------------|-----------|
{table}

---

## ✅ Recommended Action

{what_to_do}

---

## 🔍 AWS CloudTrail Correlation

To correlate who made this change in the AWS Console / CLI:
```bash
aws cloudtrail lookup-events \\
  --lookup-attributes AttributeKey=ResourceName,AttributeValue={first_phys_id} \\
  --start-time $(date -u -d "6 hours ago" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "{start_date}T00:00:00Z") \\
  --region us-east-1
```

> *This PR was generated by the Terraform Drift Detection & Auto-Remediation pipeline (`{cycle_id}`).*
"""


def build_pr_title(summary: dict) -> str:
    cycle_id = summary.get("cycle_id", "cycle")
    resource_types = list({e["resource_type"] for e in summary["drift_events"]})
    types_str = ", ".join(resource_types[:3])
    if len(resource_types) > 3:
        types_str += f" +{len(resource_types) - 3} more"
    count = summary["resource_count"]
    risk = "⚠️ HIGH" if summary["overall_risk"] == "HIGH_RISK" else "🟡 LOW"
    return f"[Drift][{risk}] {count} resource(s) drifted ({types_str}) [{cycle_id}]"


def create_pr(repo: str, branch: str, summary: dict, run_id: str, token: str) -> dict:
    url = f"https://api.github.com/repos/{repo}/pulls"

    title = build_pr_title(summary)
    body = build_pr_body(summary, run_id).replace("${REPO}", repo)

    payload = {
        "title": title,
        "head": branch,
        "base": "main",
        "body": body,
        "draft": False,
    }

    r = requests.post(url, headers=gh_headers(token), json=payload)
    r.raise_for_status()
    return r.json()


def add_pr_labels(repo: str, pr_number: int, labels: list[str], token: str):
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/labels"
    try:
        r = requests.post(url, headers=gh_headers(token), json={"labels": labels})
        if r.status_code not in (200, 201):
            print(f"Warning: could not add labels: {r.status_code} {r.text}")
    except Exception as e:
        print(f"Warning: add labels error: {e}")


def add_pr_reviewers(repo: str, pr_number: int, reviewers: list[str], token: str):
    if not reviewers:
        return
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/requested_reviewers"
    try:
        r = requests.post(url, headers=gh_headers(token), json={"reviewers": reviewers})
        if r.status_code not in (200, 201):
            print(f"Warning: could not add reviewers: {r.status_code} {r.text}")
    except Exception as e:
        print(f"Warning: add reviewers error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Create a drift remediation PR via GitHub API with deduplication")
    parser.add_argument("--branch", required=True, help="Branch name to open PR from")
    parser.add_argument("--drift-summary", required=True, help="Path to drift-summary.json")
    parser.add_argument("--repo", required=True, help="GitHub repo in 'org/repo' format")
    parser.add_argument("--run-id", required=True, help="GitHub Actions run ID")
    parser.add_argument(
        "--allow-duplicate",
        action="store_true",
        help="Bypass duplicate PR check and force create a new PR",
    )
    parser.add_argument(
        "--reviewers",
        default=os.environ.get("DRIFT_PR_REVIEWERS", ""),
        help="Comma-separated list of GitHub usernames to request as reviewers",
    )
    args = parser.parse_args()

    token = (
        os.environ.get("DRIFT_GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
    )
    if not token:
        print("ERROR: DRIFT_GITHUB_TOKEN, GH_TOKEN, or GITHUB_TOKEN environment variable is required", file=sys.stderr)
        sys.exit(1)

    with open(args.drift_summary, encoding="utf-8") as f:
        summary = json.load(f)

    cycle_id = summary.get("cycle_id", "drift-cycle-unknown")
    print(f"Processing drift cycle: {cycle_id}")
    print(f"Repository: {args.repo}")
    print(f"Risk level: {summary['overall_risk']}")
    print(f"Auto-apply: {summary['auto_apply']}")

    # ── Duplicate Detection ───────────────────────────────────────────────────
    if not args.allow_duplicate:
        existing_pr = find_existing_open_drift_pr(args.repo, token)
        if existing_pr:
            pr_num = existing_pr["number"]
            pr_url = existing_pr["html_url"]
            print(f"\n⚠️  [DUPLICATE DETECTED] An active drift remediation PR is already open: PR #{pr_num} ({pr_url})")
            print("Skipping creation of a redundant PR to avoid flooding repository.")

            update_comment = (
                f"### 🔄 Drift Cycle Update: `{cycle_id}`\n\n"
                f"Drift detection cycle executed at `{summary['detected_at']}`. "
                f"Infrastructure drift is still present on **{summary['resource_count']}** resource(s).\n\n"
                f"- **Overall Risk:** `{summary['overall_risk']}`\n"
                f"- **Auto-Apply:** `{summary['auto_apply']}`\n"
                f"- **Destructive Actions:** `{summary.get('has_destructive_changes', False)}`\n"
                f"- **CI Run:** [#{args.run_id}](https://github.com/{args.repo}/actions/runs/{args.run_id})\n\n"
                f"Please review or merge this active PR to remediate drift."
            )
            post_pr_comment(args.repo, pr_num, update_comment, token)
            return

    # Ensure required labels exist
    ensure_label_exists(args.repo, "drift-detection", "0075ca", "Automated drift detection", token)
    ensure_label_exists(args.repo, "auto-apply", "0e8a16", "Safe for automatic remediation", token)
    ensure_label_exists(args.repo, "requires-approval", "e4e669", "High-risk — human approval required", token)
    ensure_label_exists(args.repo, "destructive", "b60205", "Destructive deletion or replacement", token)
    ensure_label_exists(args.repo, "terraform", "1d76db", "Terraform infrastructure change", token)

    pr = create_pr(args.repo, args.branch, summary, args.run_id, token)
    pr_number = pr["number"]
    pr_url = pr["html_url"]

    print(f"✅ PR #{pr_number} created: {pr_url}")

    # Apply labels
    labels = ["drift-detection", "terraform"]
    if summary["auto_apply"]:
        labels.append("auto-apply")
    else:
        labels.append("requires-approval")

    if summary.get("has_destructive_changes"):
        labels.append("destructive")

    add_pr_labels(args.repo, pr_number, labels, token)

    # Request reviewers for high-risk PRs
    if summary["overall_risk"] == "HIGH_RISK" and args.reviewers:
        reviewers = [r.strip() for r in args.reviewers.split(",") if r.strip()]
        add_pr_reviewers(args.repo, pr_number, reviewers, token)
        print(f"Reviewers requested: {reviewers}")

    print(f"\nPR #{pr_number} successfully prepared for cycle {cycle_id}")


if __name__ == "__main__":
    main()
