"""Tests for the IAM role creation outside business hours detection."""

from tests.conftest import create_event
from detections.aws.iam_role_creation_unusual_hours import alert_context, rule, title


class TestRuleFires:
    def test_manual_creation_at_3am(self):
        event = create_event(
            eventTime="2026-01-15T02:00:00Z",
            requestParameters={"roleName": "suspicious-role"},
        )
        assert rule(event) is True

    def test_manual_creation_on_weekend(self):
        # 2026-04-18 is a Saturday
        event = create_event(
            eventTime="2026-04-18T12:00:00Z",
            requestParameters={"roleName": "weekend-role"},
        )
        assert rule(event) is True

    def test_unknown_user_off_hours(self):
        event = create_event(
            eventTime="2026-01-15T22:00:00Z",
            userIdentity={
                "type": "IAMUser",
                "arn": "arn:aws:iam::111111111111:user/unknown-actor",
                "userName": "unknown-actor",
            },
            requestParameters={"roleName": "exfil-role"},
        )
        assert rule(event) is True

    def test_late_night_creation(self):
        event = create_event(
            eventTime="2026-03-10T23:30:00Z",
            requestParameters={"roleName": "late-role"},
        )
        assert rule(event) is True


class TestRuleIgnores:
    def test_terraform_role_creation(self):
        event = create_event(
            eventTime="2026-01-15T02:00:00Z",
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/terraform-deploy",
            },
            userAgent="aws-sdk-go/1.44.0 (go1.19; linux; amd64) APN/1.0 HashiCorp/1.0 Terraform/1.5.0",
            requestParameters={"roleName": "lambda-execution-role"},
        )
        assert rule(event) is False

    def test_github_actions_role_creation(self):
        event = create_event(
            eventTime="2026-01-15T03:00:00Z",
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/github-actions-deploy",
            },
            requestParameters={"roleName": "deploy-role"},
        )
        assert rule(event) is False

    def test_during_business_hours(self):
        event = create_event(
            eventTime="2026-04-15T10:00:00Z",
            requestParameters={"roleName": "normal-role"},
        )
        assert rule(event) is False

    def test_infrastructure_role_name(self):
        event = create_event(
            eventTime="2026-01-15T02:00:00Z",
            requestParameters={"roleName": "terraform-state-role"},
        )
        assert rule(event) is False

    def test_wrong_event_name(self):
        event = create_event(
            eventName="DeleteRole",
            eventTime="2026-01-15T02:00:00Z",
        )
        assert rule(event) is False

    def test_cloudformation_user_agent(self):
        event = create_event(
            eventTime="2026-01-15T02:00:00Z",
            userAgent="cloudformation.amazonaws.com",
            requestParameters={"roleName": "stack-role"},
        )
        assert rule(event) is False


class TestTitle:
    def test_title_format(self):
        event = create_event(
            eventTime="2026-01-15T02:00:00Z",
            requestParameters={"roleName": "test-role"},
            recipientAccountId="111111111111",
        )
        result = title(event)
        assert "test-role" in result
        assert "111111111111" in result
        assert "production" in result


class TestAlertContext:
    def test_context_contains_required_fields(self):
        event = create_event(
            eventTime="2026-01-15T02:00:00Z",
            requestParameters={"roleName": "test-role"},
        )
        ctx = alert_context(event)
        assert ctx["role_name"] == "test-role"
        assert ctx["severity"] == "High"
        assert ctx["mitre_tactic"] == "Persistence"
        assert ctx["mitre_technique"] == "T1136 - Create Account"
        assert ctx["environment"] == "production"
        assert "principal_arn" in ctx
        assert "source_ip" in ctx
