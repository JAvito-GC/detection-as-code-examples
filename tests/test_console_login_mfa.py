"""Tests for the console login without MFA detection."""

from tests.conftest import create_event
from detections.aws.console_login_without_mfa import alert_context, rule, title


class TestRuleFires:
    def test_login_without_mfa(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        assert rule(event) is True

    def test_login_without_mfa_different_user(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            userIdentity={
                "type": "IAMUser",
                "arn": "arn:aws:iam::111111111111:user/contractor",
                "userName": "contractor",
            },
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        assert rule(event) is True


class TestRuleIgnores:
    def test_login_with_mfa(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            additionalEventData={"MFAUsed": "Yes"},
            responseElements={"ConsoleLogin": "Success"},
        )
        assert rule(event) is False

    def test_sso_login_without_mfa(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            userAgent="aws-sso",
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        assert rule(event) is False

    def test_saml_federated_login(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            userIdentity={
                "type": "SAMLUser",
                "arn": "arn:aws:iam::111111111111:saml-provider/okta",
                "userName": "federated-user",
            },
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        assert rule(event) is False

    def test_service_account_login(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            userIdentity={
                "type": "IAMUser",
                "arn": "arn:aws:iam::111111111111:user/svc-monitoring",
                "userName": "svc-monitoring",
            },
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        assert rule(event) is False

    def test_failed_login_without_mfa(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Failure"},
        )
        assert rule(event) is False

    def test_non_login_event(self):
        event = create_event(
            eventName="CreateUser",
            additionalEventData={"MFAUsed": "No"},
        )
        assert rule(event) is False

    def test_assumed_role_sso(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            userIdentity={
                "type": "AssumedRole",
                "arn": "arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin",
            },
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        assert rule(event) is False


class TestTitle:
    def test_title_includes_username(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        result = title(event)
        assert "jmorales" in result
        assert "without MFA" in result


class TestAlertContext:
    def test_context_fields(self):
        event = create_event(
            eventName="ConsoleLogin",
            eventSource="signin.amazonaws.com",
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
        ctx = alert_context(event)
        assert ctx["severity"] == "High"
        assert ctx["mfa_used"] == "No"
        assert ctx["login_result"] == "Success"
        assert ctx["mitre_technique"] == "T1078 - Valid Accounts"
