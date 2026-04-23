"""Detect S3 bucket policy changes that expose buckets to the public.

Monitors PutBucketPolicy and PutBucketAcl events for principals or ACL
grants that allow public access. Known public buckets (static sites,
public datasets) are excluded to reduce noise.

MITRE ATT&CK:
    Tactic: Exfiltration
    Technique: T1537 - Transfer Data to Cloud Account
    Also relevant:
    Tactic: Collection
    Technique: T1530 - Data from Cloud Storage
"""

import json
from typing import Optional

from detections.helpers import (
    deep_get,
    get_account_environment,
    get_account_id,
    get_principal_arn,
    get_source_ip,
    is_known_automation,
)

SEVERITY = "Critical"
TACTIC = "Exfiltration"
TECHNIQUE = "T1537 - Transfer Data to Cloud Account"
DESCRIPTION = (
    "S3 bucket policy or ACL change that grants public access. "
    "Data exposure via misconfigured S3 buckets is a top cloud risk."
)
LOG_TYPE = "AWS.CloudTrail"

KNOWN_PUBLIC_BUCKETS = [
    "company-public-assets",
    "company-static-website",
    "company-public-datasets",
    "company-press-releases",
]

PUBLIC_ACCESS_INDICATORS = [
    "*",
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
]

RELEVANT_EVENTS = ["PutBucketPolicy", "PutBucketAcl"]


def _get_bucket_name(event: dict) -> str:
    return deep_get(event, "requestParameters.bucketName", "")


def _is_known_public_bucket(bucket_name: str) -> bool:
    return bucket_name in KNOWN_PUBLIC_BUCKETS


def _policy_grants_public_access(event: dict) -> bool:
    """Check if a PutBucketPolicy event contains a public principal."""
    policy_str = deep_get(event, "requestParameters.bucketPolicy.Statement")
    if policy_str is None:
        policy_str = deep_get(event, "requestParameters.policy")

    if policy_str is None:
        return False

    if isinstance(policy_str, str):
        try:
            policy = json.loads(policy_str)
            statements = policy.get("Statement", [])
        except (json.JSONDecodeError, AttributeError):
            return False
    elif isinstance(policy_str, list):
        statements = policy_str
    else:
        return False

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})
        if principal == "*":
            return True
        if isinstance(principal, dict):
            aws_principal = principal.get("AWS", "")
            if aws_principal == "*" or (
                isinstance(aws_principal, list) and "*" in aws_principal
            ):
                return True

    return False


def _acl_grants_public_access(event: dict) -> bool:
    """Check if a PutBucketAcl event contains public grants."""
    grants = deep_get(event, "requestParameters.AccessControlPolicy.AccessControlList.Grant", [])
    if not isinstance(grants, list):
        return False

    for grant in grants:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI", "")
        if uri in PUBLIC_ACCESS_INDICATORS:
            return True

    acl_header = deep_get(event, "requestParameters.x-amz-acl", "")
    if acl_header in ("public-read", "public-read-write", "authenticated-read"):
        return True

    return False


def rule(event: dict) -> bool:
    event_name = event.get("eventName")
    if event_name not in RELEVANT_EVENTS:
        return False

    bucket_name = _get_bucket_name(event)
    if _is_known_public_bucket(bucket_name):
        return False

    if event_name == "PutBucketPolicy":
        return _policy_grants_public_access(event)

    if event_name == "PutBucketAcl":
        return _acl_grants_public_access(event)

    return False


def title(event: dict) -> str:
    bucket_name = _get_bucket_name(event)
    principal = get_principal_arn(event)
    account_id = get_account_id(event)
    env = get_account_environment(account_id)
    return f"S3 bucket '{bucket_name}' made public by {principal} in {env} ({account_id})"


def alert_context(event: dict) -> dict:
    account_id = get_account_id(event)
    return {
        "principal_arn": get_principal_arn(event),
        "bucket_name": _get_bucket_name(event),
        "event_name": event.get("eventName"),
        "event_time": event.get("eventTime"),
        "source_ip": get_source_ip(event),
        "account_id": account_id,
        "environment": get_account_environment(account_id),
        "request_parameters": event.get("requestParameters"),
        "severity": SEVERITY,
        "mitre_tactic": TACTIC,
        "mitre_technique": TECHNIQUE,
    }
