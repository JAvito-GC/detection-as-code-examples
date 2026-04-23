"""Pytest fixtures and event builders for detection rule tests.

Provides a factory function that builds realistic CloudTrail events
with sensible defaults. Individual tests override only the fields
relevant to each scenario.
"""

import copy
from typing import Any, Optional

import pytest


BASE_CLOUDTRAIL_EVENT: dict[str, Any] = {
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDAJQABLZS4A3QDU576Q",
        "arn": "arn:aws:iam::111111111111:user/jmorales",
        "accountId": "111111111111",
        "userName": "jmorales",
    },
    "eventTime": "2026-04-15T14:30:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateRole",
    "awsRegion": "eu-west-1",
    "sourceIPAddress": "203.0.113.50",
    "userAgent": "aws-cli/2.15.0 Python/3.11.6",
    "requestParameters": {
        "roleName": "my-custom-role",
        "assumeRolePolicyDocument": "{}",
    },
    "responseElements": {
        "role": {
            "roleName": "my-custom-role",
            "roleId": "AROA3XFRBF23LDQWZMQHI",
            "arn": "arn:aws:iam::111111111111:role/my-custom-role",
        }
    },
    "recipientAccountId": "111111111111",
    "readOnly": False,
    "errorCode": None,
    "errorMessage": None,
    "additionalEventData": {},
}


def create_event(overrides: Optional[dict] = None, **kwargs: Any) -> dict:
    """Build a CloudTrail event with optional overrides.

    Supports both dict-style overrides and keyword arguments. Nested
    dicts are merged one level deep rather than replaced entirely.

    Usage:
        event = create_event(eventName="ConsoleLogin")
        event = create_event({"userIdentity": {"type": "Root"}})
    """
    event = copy.deepcopy(BASE_CLOUDTRAIL_EVENT)

    if overrides:
        for key, value in overrides.items():
            if isinstance(value, dict) and isinstance(event.get(key), dict):
                event[key].update(value)
            else:
                event[key] = value

    for key, value in kwargs.items():
        if isinstance(value, dict) and isinstance(event.get(key), dict):
            event[key].update(value)
        else:
            event[key] = value

    return event


@pytest.fixture
def make_event():
    """Fixture that returns the create_event factory."""
    return create_event


@pytest.fixture
def cloudtrail_iam_create_role():
    """Standard IAM CreateRole event during business hours."""
    return create_event()


@pytest.fixture
def cloudtrail_iam_create_role_off_hours():
    """IAM CreateRole event at 3 AM Madrid time (01:00 UTC in winter)."""
    return create_event(eventTime="2026-01-15T02:00:00Z")


@pytest.fixture
def cloudtrail_console_login_no_mfa():
    """Console login without MFA."""
    return create_event(
        eventName="ConsoleLogin",
        eventSource="signin.amazonaws.com",
        additionalEventData={"MFAUsed": "No"},
        responseElements={"ConsoleLogin": "Success"},
    )


@pytest.fixture
def cloudtrail_console_login_with_mfa():
    """Console login with MFA."""
    return create_event(
        eventName="ConsoleLogin",
        eventSource="signin.amazonaws.com",
        additionalEventData={"MFAUsed": "Yes"},
        responseElements={"ConsoleLogin": "Success"},
    )


@pytest.fixture
def cloudtrail_root_event():
    """Root account API call."""
    return create_event(
        eventName="StopInstances",
        eventSource="ec2.amazonaws.com",
        userIdentity={
            "type": "Root",
            "principalId": "111111111111",
            "arn": "arn:aws:iam::111111111111:root",
            "accountId": "111111111111",
        },
    )


@pytest.fixture
def guardduty_high_severity():
    """GuardDuty finding with severity 8.0."""
    return {
        "detail": {
            "id": "finding-12345",
            "type": "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
            "severity": 8.0,
            "accountId": "111111111111",
            "region": "eu-west-1",
            "description": "EC2 instance communicating with a known malicious IP.",
            "resource": {
                "resourceType": "Instance",
                "instanceDetails": {
                    "instanceId": "i-0abc123def456",
                },
            },
            "service": {
                "eventFirstSeen": "2026-04-15T10:00:00Z",
                "eventLastSeen": "2026-04-15T14:00:00Z",
                "count": 5,
            },
        },
        "recipientAccountId": "111111111111",
    }
