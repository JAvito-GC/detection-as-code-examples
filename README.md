# Detection-as-Code Examples

Curated detection rules for cloud security monitoring, structured as code with unit tests. Focused on AWS CloudTrail events following a consistent, testable pattern inspired by modern SIEM-as-code platforms.

These examples demonstrate how to reduce false positives through contextual filtering, business-hour awareness, and automation exclusion -- the same approach that achieved a **60% reduction in false positives** across a multi-account AWS environment.

Read the full write-up: [Detection-as-Code: 60% menos falsos positivos](https://javiermorales.tech/blog/detection-as-code-60-menos-falsos-positivos/)

## Structure

```
detection-as-code-examples/
├── detections/
│   ├── helpers.py                          # Shared utilities (time, account context, automation checks)
│   └── aws/
│       ├── iam_role_creation_unusual_hours.py   # IAM role creation outside business hours
│       ├── console_login_without_mfa.py         # Console login without MFA
│       ├── s3_bucket_made_public.py             # S3 bucket exposed to public
│       ├── guardduty_high_severity.py           # GuardDuty high-severity enrichment
│       ├── root_account_usage.py                # Root account API activity
│       └── cloudtrail_logging_disabled.py       # CloudTrail tampering (defense evasion)
├── tests/
│   ├── conftest.py                         # Pytest fixtures and event builders
│   ├── test_iam_role_creation.py
│   ├── test_console_login_mfa.py
│   ├── test_cloudtrail_logging_disabled.py
│   └── test_helpers.py
└── .github/
    └── workflows/
        └── test.yml                        # CI pipeline
```

## Detection Pattern

Every detection follows a consistent interface:

```python
# Metadata
SEVERITY = "High"
TACTIC = "Persistence"
TECHNIQUE = "T1136 - Create Account"
DESCRIPTION = "Detects IAM role creation outside business hours by non-automation users."

def rule(event: dict) -> bool:
    """Return True if the event should fire an alert."""

def title(event: dict) -> str:
    """Return a human-readable alert title."""

def alert_context(event: dict) -> dict:
    """Return enrichment data attached to the alert."""
```

This mirrors detection-as-code platforms where each detection is a Python module with a predictable contract that can be tested, versioned, and reviewed like any other code.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/JAvito-GC/detection-as-code-examples.git
cd detection-as-code-examples

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install pytest pytz

# Run all tests
pytest -v
```

## Key Principles

- **Every rule is testable.** Unit tests validate both true positives and true negatives using realistic CloudTrail event fixtures.
- **Shared helpers reduce duplication.** Business-hour checks, automation identification, and account context live in one place.
- **Context cuts noise.** Filtering by time, actor identity, and account environment eliminates alerts that waste analyst time.
- **MITRE ATT&CK mapping.** Each detection maps to a tactic and technique for consistent triage and reporting.

## Requirements

- Python 3.9+
- pytest
- pytz

## Author

**Javier Morales** -- Staff Security Engineer | Detection Engineering | AI-Driven Security Operations

- Website: [javiermorales.tech](https://javiermorales.tech)
- GitHub: [JAvito-GC](https://github.com/JAvito-GC)

## License

[MIT](LICENSE)
