"""Detect AWS Console logins without MFA.

Console access without multi-factor authentication is a high-severity
finding. SSO-federated logins and service accounts are excluded since
they use alternative authentication mechanisms.

MITRE ATT&CK:
    Tactic: Initial Access
    Technique: T1078 - Valid Accounts
    Sub-technique: T1078.004 - Cloud Accounts
"""

from detections.helpers import (
    deep_get,
    get_account_environment,
    get_account_id,
    get_principal_arn,
    get_source_ip,
)

SEVERITY = "High"
TACTIC = "Initial Access"
TECHNIQUE = "T1078 - Valid Accounts"
DESCRIPTION = (
    "AWS Console login without MFA. Indicates a credential may be compromised "
    "or MFA enforcement is not configured for this user."
)
LOG_TYPE = "AWS.CloudTrail"

SSO_USER_AGENTS = [
    "aws-sso",
    "saml",
    "okta",
    "auth0",
    "azure-ad",
]

SERVICE_ACCOUNT_PATTERNS = [
    "svc-",
    "service-account",
    "automation-",
    "bot-",
]


def _is_sso_login(event: dict) -> bool:
    user_agent = event.get("userAgent", "").lower()
    for pattern in SSO_USER_AGENTS:
        if pattern in user_agent:
            return True

    user_identity = event.get("userIdentity", {})
    if user_identity.get("type") == "SAMLUser":
        return True
    if user_identity.get("type") == "AssumedRole":
        arn = user_identity.get("arn", "")
        if "saml-provider" in arn.lower() or "sso" in arn.lower():
            return True

    return False


def _is_service_account(event: dict) -> bool:
    principal = get_principal_arn(event).lower()
    username = event.get("userIdentity", {}).get("userName", "").lower()
    for pattern in SERVICE_ACCOUNT_PATTERNS:
        if pattern in principal or pattern in username:
            return True
    return False


def rule(event: dict) -> bool:
    if event.get("eventName") != "ConsoleLogin":
        return False

    mfa_used = deep_get(event, "additionalEventData.MFAUsed")
    if mfa_used != "No":
        return False

    if _is_sso_login(event):
        return False

    if _is_service_account(event):
        return False

    response = deep_get(event, "responseElements.ConsoleLogin")
    if response != "Success":
        return False

    return True


def title(event: dict) -> str:
    username = event.get("userIdentity", {}).get("userName", "unknown")
    account_id = get_account_id(event)
    env = get_account_environment(account_id)
    return f"Console login without MFA by '{username}' in {env} ({account_id})"


def alert_context(event: dict) -> dict:
    account_id = get_account_id(event)
    return {
        "principal_arn": get_principal_arn(event),
        "username": event.get("userIdentity", {}).get("userName"),
        "event_time": event.get("eventTime"),
        "source_ip": get_source_ip(event),
        "account_id": account_id,
        "environment": get_account_environment(account_id),
        "user_agent": event.get("userAgent"),
        "mfa_used": deep_get(event, "additionalEventData.MFAUsed"),
        "login_result": deep_get(event, "responseElements.ConsoleLogin"),
        "severity": SEVERITY,
        "mitre_tactic": TACTIC,
        "mitre_technique": TECHNIQUE,
    }
