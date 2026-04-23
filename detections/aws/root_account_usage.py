"""Detect any API activity by the AWS root account.

Root account usage should be near-zero in a well-governed AWS environment.
Expected exceptions (billing console access) are excluded. Any other
root API call is a critical finding.

MITRE ATT&CK:
    Tactic: Privilege Escalation
    Technique: T1078.004 - Valid Accounts: Cloud Accounts
"""

from detections.helpers import (
    get_account_environment,
    get_account_id,
    get_source_ip,
    is_root_user,
)

SEVERITY = "Critical"
TACTIC = "Privilege Escalation"
TECHNIQUE = "T1078.004 - Valid Accounts: Cloud Accounts"
DESCRIPTION = (
    "Root account API activity detected. Root should only be used for "
    "initial account setup and break-glass scenarios."
)
LOG_TYPE = "AWS.CloudTrail"

EXPECTED_ROOT_EVENTS = [
    "ConsoleLogin",
    "CreateServiceLinkedRole",
]

BILLING_EVENTS = [
    "GetBillingData",
    "GetCostAndUsage",
    "GetCostForecast",
    "DescribeBillingGroup",
]

EXPECTED_ROOT_SERVICES = [
    "billing.amazonaws.com",
    "ce.amazonaws.com",
    "health.amazonaws.com",
    "support.amazonaws.com",
]


def _is_expected_root_operation(event: dict) -> bool:
    event_name = event.get("eventName", "")
    event_source = event.get("eventSource", "")

    if event_name in BILLING_EVENTS:
        return True

    if event_source in EXPECTED_ROOT_SERVICES:
        return True

    return False


def rule(event: dict) -> bool:
    if not is_root_user(event):
        return False

    if _is_expected_root_operation(event):
        return False

    if event.get("readOnly") is True:
        event_source = event.get("eventSource", "")
        if event_source in EXPECTED_ROOT_SERVICES:
            return False

    return True


def title(event: dict) -> str:
    event_name = event.get("eventName", "unknown")
    account_id = get_account_id(event)
    env = get_account_environment(account_id)
    source_ip = get_source_ip(event)
    return f"Root account activity: {event_name} from {source_ip} in {env} ({account_id})"


def alert_context(event: dict) -> dict:
    account_id = get_account_id(event)
    return {
        "event_name": event.get("eventName"),
        "event_source": event.get("eventSource"),
        "event_time": event.get("eventTime"),
        "source_ip": get_source_ip(event),
        "user_agent": event.get("userAgent"),
        "account_id": account_id,
        "environment": get_account_environment(account_id),
        "aws_region": event.get("awsRegion"),
        "read_only": event.get("readOnly"),
        "error_code": event.get("errorCode"),
        "error_message": event.get("errorMessage"),
        "severity": SEVERITY,
        "mitre_tactic": TACTIC,
        "mitre_technique": TECHNIQUE,
    }
