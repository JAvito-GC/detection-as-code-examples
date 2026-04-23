"""Detect IAM role creation outside business hours by non-automation users.

Roles created manually during off-hours are a strong indicator of unauthorized
activity. Automation (Terraform, CI/CD) is excluded because it legitimately
operates around the clock.

MITRE ATT&CK:
    Tactic: Persistence
    Technique: T1136 - Create Account
    Sub-technique: T1136.003 - Cloud Account
"""

from typing import Optional

from detections.helpers import (
    get_account_environment,
    get_account_id,
    get_principal_arn,
    get_source_ip,
    is_infrastructure_role,
    is_known_automation,
    is_outside_business_hours,
)

SEVERITY = "High"
TACTIC = "Persistence"
TECHNIQUE = "T1136 - Create Account"
DESCRIPTION = (
    "IAM role creation outside business hours by a non-automation principal. "
    "Manual role creation during off-hours warrants investigation."
)
LOG_TYPE = "AWS.CloudTrail"


def rule(event: dict) -> bool:
    if event.get("eventName") != "CreateRole":
        return False

    if is_known_automation(event):
        return False

    if is_infrastructure_role(event):
        return False

    if not is_outside_business_hours(event):
        return False

    return True


def title(event: dict) -> str:
    principal = get_principal_arn(event)
    role_name = event.get("requestParameters", {}).get("roleName", "unknown")
    account_id = get_account_id(event)
    env = get_account_environment(account_id)
    return f"IAM role '{role_name}' created outside business hours by {principal} in {env} ({account_id})"


def alert_context(event: dict) -> dict:
    account_id = get_account_id(event)
    return {
        "principal_arn": get_principal_arn(event),
        "role_name": event.get("requestParameters", {}).get("roleName"),
        "event_time": event.get("eventTime"),
        "source_ip": get_source_ip(event),
        "account_id": account_id,
        "environment": get_account_environment(account_id),
        "user_agent": event.get("userAgent"),
        "severity": SEVERITY,
        "mitre_tactic": TACTIC,
        "mitre_technique": TECHNIQUE,
    }
