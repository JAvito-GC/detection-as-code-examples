"""Shared helper functions for detection rules.

Centralizing context-aware filtering here is what drives false positive
reduction. Instead of duplicating exclusion logic across dozens of rules,
every detection imports from one source of truth.
"""

from datetime import datetime
from typing import Optional

import pytz


KNOWN_AUTOMATION_ARNS = [
    "arn:aws:iam::*:role/terraform-*",
    "arn:aws:iam::*:role/github-actions-*",
    "arn:aws:iam::*:role/jenkins-*",
    "arn:aws:iam::*:role/atlantis-*",
    "arn:aws:iam::*:role/AWSServiceRole*",
    "arn:aws:iam::*:role/OrganizationAccountAccessRole",
    "arn:aws:iam::*:role/aws-reserved/*",
]

KNOWN_AUTOMATION_PATTERNS = [
    "terraform-",
    "github-actions-",
    "jenkins-",
    "atlantis-",
    "AWSServiceRole",
    "OrganizationAccountAccessRole",
    "codepipeline-",
    "cloudformation-",
    "lambda-execution-",
]

INFRASTRUCTURE_ROLE_PATTERNS = [
    "terraform",
    "cloudformation",
    "cdk-",
    "pulumi",
    "serverless-",
    "lambda-execution",
    "codepipeline",
    "codebuild",
    "ecs-task-",
]

ACCOUNT_ENVIRONMENT_MAP: dict[str, str] = {
    "111111111111": "production",
    "222222222222": "staging",
    "333333333333": "development",
    "444444444444": "sandbox",
    "555555555555": "security",
    "666666666666": "logging",
    "777777777777": "shared-services",
}

BUSINESS_HOURS_START = 8
BUSINESS_HOURS_END = 20


def get_principal_arn(event: dict) -> str:
    user_identity = event.get("userIdentity", {})
    return user_identity.get("arn", "")


def get_user_agent(event: dict) -> str:
    return event.get("userAgent", "")


def get_source_ip(event: dict) -> str:
    return event.get("sourceIPAddress", "")


def get_account_id(event: dict) -> str:
    return event.get("recipientAccountId", "")


def get_event_time(event: dict) -> Optional[datetime]:
    raw = event.get("eventTime", "")
    if not raw:
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=pytz.utc)
    except ValueError:
        return None


def is_known_automation(event: dict) -> bool:
    """Check if the event principal matches a known automation identity.

    Compares the principal ARN and user agent against known CI/CD and
    infrastructure automation patterns. This single check eliminates a
    large percentage of false positives from routine infrastructure changes.
    """
    principal = get_principal_arn(event).lower()
    user_agent = get_user_agent(event).lower()

    for pattern in KNOWN_AUTOMATION_PATTERNS:
        if pattern.lower() in principal:
            return True

    automation_user_agents = [
        "terraform",
        "cloudformation",
        "pulumi",
        "atlantis",
        "aws-sdk-go",
    ]
    for agent in automation_user_agents:
        if agent in user_agent:
            return True

    return False


def is_outside_business_hours(event: dict, timezone: str = "Europe/Madrid") -> bool:
    """Check if the event occurred outside of business hours.

    Defaults to Europe/Madrid timezone (CET/CEST). Operations outside
    08:00-20:00 local time or on weekends are flagged.
    """
    event_time = get_event_time(event)
    if event_time is None:
        return False

    tz = pytz.timezone(timezone)
    local_time = event_time.astimezone(tz)

    if local_time.weekday() >= 5:
        return True

    return local_time.hour < BUSINESS_HOURS_START or local_time.hour >= BUSINESS_HOURS_END


def is_infrastructure_role(event: dict) -> bool:
    """Check if the role being created or used matches infrastructure patterns.

    Catches Terraform-managed roles, CI/CD execution roles, and Lambda
    execution roles that should not trigger alerts.
    """
    principal = get_principal_arn(event).lower()
    request_params = event.get("requestParameters", {})
    role_name = request_params.get("roleName", "").lower()

    for pattern in INFRASTRUCTURE_ROLE_PATTERNS:
        if pattern in principal or pattern in role_name:
            return True

    return False


def get_account_environment(account_id: str) -> str:
    """Map an AWS account ID to its environment label.

    Returns the environment name from a static mapping. In production,
    this would query a CMDB or AWS Organizations. Unknown accounts
    default to 'unknown' which should raise investigator attention.
    """
    return ACCOUNT_ENVIRONMENT_MAP.get(account_id, "unknown")


def is_aws_service(event: dict) -> bool:
    """Check if the event was invoked by an AWS service rather than a user."""
    user_identity = event.get("userIdentity", {})
    return user_identity.get("type") == "AWSService"


def is_root_user(event: dict) -> bool:
    """Check if the event was performed by the root account."""
    user_identity = event.get("userIdentity", {})
    return user_identity.get("type") == "Root"


def deep_get(event: dict, path: str, default=None):
    """Retrieve a nested value from a dict using dot-separated path."""
    keys = path.split(".")
    value = event
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        else:
            return default
        if value is None:
            return default
    return value
