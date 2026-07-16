"""Tests for the CloudTrail tampering detection."""

from tests.conftest import create_event
from detections.aws.cloudtrail_logging_disabled import alert_context, rule, title


def _tamper_event(**kwargs):
    """CloudTrail management event with sane tampering defaults."""
    base = dict(
        eventName="StopLogging",
        eventSource="cloudtrail.amazonaws.com",
        requestParameters={"name": "org-trail"},
        errorCode=None,
    )
    base.update(kwargs)
    return create_event(**base)


class TestRuleFires:
    def test_stop_logging(self):
        assert rule(_tamper_event(eventName="StopLogging")) is True

    def test_delete_trail(self):
        assert rule(_tamper_event(eventName="DeleteTrail")) is True

    def test_update_trail_drops_multi_region(self):
        event = _tamper_event(
            eventName="UpdateTrail",
            requestParameters={"name": "org-trail", "isMultiRegionTrail": False},
        )
        assert rule(event) is True

    def test_update_trail_drops_global_events(self):
        event = _tamper_event(
            eventName="UpdateTrail",
            requestParameters={"name": "org-trail", "includeGlobalServiceEvents": False},
        )
        assert rule(event) is True


class TestRuleIgnores:
    def test_unrelated_event_name(self):
        assert rule(_tamper_event(eventName="CreateTrail")) is False

    def test_wrong_event_source(self):
        assert rule(_tamper_event(eventSource="s3.amazonaws.com")) is False

    def test_failed_api_call(self):
        assert rule(_tamper_event(errorCode="AccessDenied")) is False

    def test_update_trail_without_coverage_loss(self):
        # Reconfiguring a trail without narrowing coverage is routine.
        event = _tamper_event(
            eventName="UpdateTrail",
            requestParameters={"name": "org-trail", "isMultiRegionTrail": True},
        )
        assert rule(event) is False

    def test_terraform_automation_excluded(self):
        event = _tamper_event(
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/terraform-ci",
                "userName": "terraform-ci",
            },
        )
        assert rule(event) is False

    def test_cloudformation_user_agent_excluded(self):
        event = _tamper_event(userAgent="cloudformation.amazonaws.com")
        assert rule(event) is False


class TestTitle:
    def test_title_includes_action_and_trail(self):
        result = title(_tamper_event(eventName="StopLogging"))
        assert "StopLogging" in result
        assert "org-trail" in result


class TestAlertContext:
    def test_context_fields(self):
        ctx = alert_context(_tamper_event(eventName="DeleteTrail"))
        assert ctx["severity"] == "High"
        assert ctx["event_name"] == "DeleteTrail"
        assert ctx["trail_name"] == "org-trail"
        assert ctx["mitre_technique"] == "T1562 - Impair Defenses"
