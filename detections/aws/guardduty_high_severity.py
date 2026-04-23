"""Enrich and alert on high-severity GuardDuty findings.

GuardDuty generates findings with severity 0-10. This detection filters
for findings with severity >= 7 and enriches them with account context
for faster triage. Severity is mapped to Critical (>= 8.5) or High.

MITRE ATT&CK:
    Varies by finding type. GuardDuty covers multiple tactics including:
    - Reconnaissance (T1595)
    - Initial Access (T1190)
    - Credential Access (T1110)
    - Impact (T1496 - Crypto Mining)
"""

from typing import Optional

from detections.helpers import (
    deep_get,
    get_account_environment,
    get_account_id,
    get_principal_arn,
    get_source_ip,
)

SEVERITY = "High"
TACTIC = "Multiple"
TECHNIQUE = "Multiple"
DESCRIPTION = (
    "GuardDuty finding with severity >= 7. High-severity findings "
    "indicate active threats requiring immediate investigation."
)
LOG_TYPE = "AWS.GuardDuty"

SEVERITY_THRESHOLD = 7.0
CRITICAL_THRESHOLD = 8.5

FINDING_TYPE_TO_MITRE: dict[str, dict[str, str]] = {
    "UnauthorizedAccess": {"tactic": "Initial Access", "technique": "T1078"},
    "Recon": {"tactic": "Reconnaissance", "technique": "T1595"},
    "Trojan": {"tactic": "Execution", "technique": "T1204"},
    "CryptoCurrency": {"tactic": "Impact", "technique": "T1496"},
    "Backdoor": {"tactic": "Persistence", "technique": "T1098"},
    "Exfiltration": {"tactic": "Exfiltration", "technique": "T1537"},
    "CredentialAccess": {"tactic": "Credential Access", "technique": "T1110"},
    "Stealth": {"tactic": "Defense Evasion", "technique": "T1562"},
}


def _get_severity(event: dict) -> float:
    severity = deep_get(event, "detail.severity")
    if severity is None:
        severity = event.get("severity", 0)
    try:
        return float(severity)
    except (TypeError, ValueError):
        return 0.0


def _get_finding_type(event: dict) -> str:
    return deep_get(event, "detail.type", event.get("type", ""))


def _get_finding_category(finding_type: str) -> str:
    """Extract the top-level category from a GuardDuty finding type.

    Finding types follow the pattern: ThreatPurpose:ResourceType/ThreatFamilyName.
    """
    return finding_type.split(":")[0] if ":" in finding_type else finding_type


def _compute_severity(event: dict) -> str:
    severity_score = _get_severity(event)
    if severity_score >= CRITICAL_THRESHOLD:
        return "Critical"
    return "High"


def _get_mitre_mapping(finding_type: str) -> dict[str, str]:
    category = _get_finding_category(finding_type)
    return FINDING_TYPE_TO_MITRE.get(
        category, {"tactic": "Unknown", "technique": "Unknown"}
    )


def rule(event: dict) -> bool:
    severity = _get_severity(event)
    return severity >= SEVERITY_THRESHOLD


def title(event: dict) -> str:
    finding_type = _get_finding_type(event)
    severity_label = _compute_severity(event)
    account_id = deep_get(event, "detail.accountId", get_account_id(event))
    env = get_account_environment(account_id)
    return f"[{severity_label}] GuardDuty: {finding_type} in {env} ({account_id})"


def alert_context(event: dict) -> dict:
    finding_type = _get_finding_type(event)
    mitre = _get_mitre_mapping(finding_type)
    account_id = deep_get(event, "detail.accountId", get_account_id(event))

    resource = deep_get(event, "detail.resource", {})
    affected_resource_type = resource.get("resourceType", "Unknown") if isinstance(resource, dict) else "Unknown"

    return {
        "finding_type": finding_type,
        "finding_id": deep_get(event, "detail.id", event.get("id")),
        "severity_score": _get_severity(event),
        "computed_severity": _compute_severity(event),
        "account_id": account_id,
        "environment": get_account_environment(account_id),
        "region": deep_get(event, "detail.region", event.get("region")),
        "resource_type": affected_resource_type,
        "description": deep_get(event, "detail.description", ""),
        "mitre_tactic": mitre["tactic"],
        "mitre_technique": mitre["technique"],
        "first_seen": deep_get(event, "detail.service.eventFirstSeen"),
        "last_seen": deep_get(event, "detail.service.eventLastSeen"),
        "count": deep_get(event, "detail.service.count"),
    }
