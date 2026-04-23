"""Tests for shared helper functions."""

from tests.conftest import create_event
from detections.helpers import (
    deep_get,
    get_account_environment,
    get_event_time,
    get_principal_arn,
    is_aws_service,
    is_infrastructure_role,
    is_known_automation,
    is_outside_business_hours,
    is_root_user,
)


class TestIsKnownAutomation:
    def test_terraform_arn(self):
        event = create_event(
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/terraform-deploy",
            }
        )
        assert is_known_automation(event) is True

    def test_github_actions_arn(self):
        event = create_event(
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/github-actions-runner",
            }
        )
        assert is_known_automation(event) is True

    def test_terraform_user_agent(self):
        event = create_event(
            userAgent="aws-sdk-go/1.44.0 APN/1.0 HashiCorp/1.0 Terraform/1.5.0"
        )
        assert is_known_automation(event) is True

    def test_cloudformation_user_agent(self):
        event = create_event(userAgent="cloudformation.amazonaws.com")
        assert is_known_automation(event) is True

    def test_regular_user(self):
        event = create_event(
            userIdentity={
                "type": "IAMUser",
                "arn": "arn:aws:iam::111111111111:user/jmorales",
            },
            userAgent="aws-cli/2.15.0 Python/3.11.6",
        )
        assert is_known_automation(event) is False

    def test_jenkins_arn(self):
        event = create_event(
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/jenkins-deploy",
            }
        )
        assert is_known_automation(event) is True

    def test_service_linked_role(self):
        event = create_event(
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/AWSServiceRoleForAutoScaling",
            }
        )
        assert is_known_automation(event) is True


class TestIsOutsideBusinessHours:
    def test_3am_utc_is_outside_madrid(self):
        # 3 AM UTC = 4 AM CET (winter) = outside business hours
        event = create_event(eventTime="2026-01-15T03:00:00Z")
        assert is_outside_business_hours(event) is True

    def test_10am_utc_is_inside_madrid(self):
        # 10 AM UTC = 11 AM CET (winter) = inside business hours
        event = create_event(eventTime="2026-01-15T10:00:00Z")
        assert is_outside_business_hours(event) is False

    def test_weekend_midday(self):
        # 2026-04-18 is a Saturday
        event = create_event(eventTime="2026-04-18T12:00:00Z")
        assert is_outside_business_hours(event) is True

    def test_friday_afternoon(self):
        # 2026-04-17 is a Friday, 15 UTC = 17 CEST = inside
        event = create_event(eventTime="2026-04-17T15:00:00Z")
        assert is_outside_business_hours(event) is False

    def test_custom_timezone_us_east(self):
        # 14 UTC = 10 AM US/Eastern = inside business hours
        event = create_event(eventTime="2026-04-15T14:00:00Z")
        assert is_outside_business_hours(event, timezone="US/Eastern") is False

    def test_missing_event_time(self):
        event = create_event(eventTime="")
        assert is_outside_business_hours(event) is False

    def test_late_evening_madrid(self):
        # 21 UTC = 22 CET (winter) = outside business hours
        event = create_event(eventTime="2026-01-15T21:00:00Z")
        assert is_outside_business_hours(event) is True


class TestIsInfrastructureRole:
    def test_terraform_role_name(self):
        event = create_event(
            requestParameters={"roleName": "terraform-state-role"}
        )
        assert is_infrastructure_role(event) is True

    def test_lambda_execution_role(self):
        event = create_event(
            requestParameters={"roleName": "lambda-execution-api-handler"}
        )
        assert is_infrastructure_role(event) is True

    def test_cdk_role(self):
        event = create_event(
            requestParameters={"roleName": "cdk-bootstrap-role"}
        )
        assert is_infrastructure_role(event) is True

    def test_custom_role(self):
        event = create_event(
            requestParameters={"roleName": "data-analyst-role"}
        )
        assert is_infrastructure_role(event) is False

    def test_cloudformation_principal(self):
        event = create_event(
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/cloudformation-deploy",
            }
        )
        assert is_infrastructure_role(event) is True


class TestGetAccountEnvironment:
    def test_production_account(self):
        assert get_account_environment("111111111111") == "production"

    def test_staging_account(self):
        assert get_account_environment("222222222222") == "staging"

    def test_sandbox_account(self):
        assert get_account_environment("444444444444") == "sandbox"

    def test_unknown_account(self):
        assert get_account_environment("999999999999") == "unknown"


class TestDeepGet:
    def test_simple_key(self):
        event = {"key": "value"}
        assert deep_get(event, "key") == "value"

    def test_nested_key(self):
        event = {"a": {"b": {"c": "deep"}}}
        assert deep_get(event, "a.b.c") == "deep"

    def test_missing_key(self):
        event = {"a": {"b": 1}}
        assert deep_get(event, "a.c", "default") == "default"

    def test_none_default(self):
        event = {}
        assert deep_get(event, "missing") is None

    def test_non_dict_intermediate(self):
        event = {"a": "string"}
        assert deep_get(event, "a.b", "fallback") == "fallback"


class TestIsRootUser:
    def test_root_user(self):
        event = create_event(
            userIdentity={"type": "Root", "arn": "arn:aws:iam::111111111111:root"}
        )
        assert is_root_user(event) is True

    def test_iam_user(self):
        event = create_event()
        assert is_root_user(event) is False


class TestIsAwsService:
    def test_aws_service(self):
        event = create_event(
            userIdentity={"type": "AWSService", "invokedBy": "elasticmapreduce.amazonaws.com"}
        )
        assert is_aws_service(event) is True

    def test_not_aws_service(self):
        event = create_event()
        assert is_aws_service(event) is False


class TestGetEventTime:
    def test_valid_time(self):
        event = create_event(eventTime="2026-04-15T14:30:00Z")
        result = get_event_time(event)
        assert result is not None
        assert result.hour == 14

    def test_empty_time(self):
        event = create_event(eventTime="")
        assert get_event_time(event) is None

    def test_invalid_time(self):
        event = create_event(eventTime="not-a-date")
        assert get_event_time(event) is None
