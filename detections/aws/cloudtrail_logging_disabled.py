"""Detect tampering with AWS CloudTrail logging.

Disabling, deleting, or narrowing a CloudTrail is a classic defense-evasion
move: an attacker who has gained credentials blinds the audit trail before
acting further. Legitimate infrastructure automation (Terraform, CloudFormation)
routinely updates trails, so those principals are excluded to keep this
high-signal.

Three tampering shapes are covered:
  * StopLogging  -- logging turned off outright
  * DeleteTrail  -- the trail removed entirely
  * UpdateTrail  -- reconfigured to reduce coverage (drops multi-region or
                    global service events), a quieter way to create blind spots

MITRE ATT&CK:
    Tactic: Defense Evasion
    Technique: T1562 - Impair Defenses
    Sub-technique: T1562.008 - Disable or Modify Cloud Logs
"""

from detections.helpers import (
    deep_get,
    get_account_environment,
    get_account_id,
    get_principal_arn,
    get_source_ip,
    is_known_automation,
)

SEVERITY = "High"
TACTIC = "Defense Evasion"
TECHNIQUE = "T1562 - Impair Defenses"
DESCRIPTION = (
    "CloudTrail logging was stopped, deleted, or reconfigured to reduce "
    "coverage. Commonly used to blind the audit trail before further activity."
)
LOG_TYPE = "AWS.CloudTrail"

TAMPER_EVENTS = {"StopLogging", "DeleteTrail", "UpdateTrail"}


def _reduces_coverage(event: dict) -> bool:
    """Return True if an UpdateTrail narrows the trail's visibility.

    Flipping off multi-region collection or global service events shrinks
    what the trail records -- a subtle blind spot rather than a full stop.
    """
    params = event.get("requestParameters", {})
    if params.get("isMultiRegionTrail") is False:
        return True
    if params.get("includeGlobalServiceEvents") is False:
        return True
    return False


def rule(event: dict) -> bool:
    if event.get("eventSource") != "cloudtrail.amazonaws.com":
        return False

    event_name = event.get("eventName")
    if event_name not in TAMPER_EVENTS:
        return False

    # A failed API call created no blind spot.
    if event.get("errorCode"):
        return False

    # Trails are legitimately managed as code; don't cry wolf on automation.
    if is_known_automation(event):
        return False

    if event_name == "UpdateTrail":
        return _reduces_coverage(event)

    return True


def title(event: dict) -> str:
    account_id = get_account_id(event)
    env = get_account_environment(account_id)
    trail = deep_get(event, "requestParameters.name") or "unknown-trail"
    action = event.get("eventName")
    return f"CloudTrail tampering ({action}) on '{trail}' in {env} ({account_id})"


def alert_context(event: dict) -> dict:
    account_id = get_account_id(event)
    return {
        "principal_arn": get_principal_arn(event),
        "event_name": event.get("eventName"),
        "trail_name": deep_get(event, "requestParameters.name"),
        "event_time": event.get("eventTime"),
        "source_ip": get_source_ip(event),
        "account_id": account_id,
        "environment": get_account_environment(account_id),
        "user_agent": event.get("userAgent"),
        "is_multi_region": deep_get(event, "requestParameters.isMultiRegionTrail"),
        "include_global_events": deep_get(
            event, "requestParameters.includeGlobalServiceEvents"
        ),
        "severity": SEVERITY,
        "mitre_tactic": TACTIC,
        "mitre_technique": TECHNIQUE,
    }
