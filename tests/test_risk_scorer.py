"""
Unit tests for risk_scorer.py
Validates scoring logic and lifetime mapping across all three risk tiers.

Run with:
    python3 -m pytest tests/test_risk_scorer.py -v
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from risk_scorer import compute_risk_score, get_dynamic_lifetime


class TestComputeRiskScore:

    def test_low_risk_all_trusted(self):
        """Known IP, business hours, no failures, MFA used → score 0."""
        score = compute_risk_score(
            ip_known=True,
            off_hours=False,
            failed_logins=0,
            mfa_used=True
        )
        assert score == 0

    def test_low_risk_off_hours_only(self):
        """Only off-hours signal triggered → score 2."""
        score = compute_risk_score(
            ip_known=True,
            off_hours=True,
            failed_logins=0,
            mfa_used=True
        )
        assert score == 2

    def test_medium_risk_unknown_ip(self):
        """Unknown IP, business hours, no failures, MFA used → score 3."""
        score = compute_risk_score(
            ip_known=False,
            off_hours=False,
            failed_logins=0,
            mfa_used=True
        )
        assert score == 3

    def test_medium_risk_unknown_ip_off_hours(self):
        """Unknown IP + off-hours → score 5."""
        score = compute_risk_score(
            ip_known=False,
            off_hours=True,
            failed_logins=0,
            mfa_used=True
        )
        assert score == 5

    def test_high_risk_all_signals(self):
        """All four signals triggered → score 10."""
        score = compute_risk_score(
            ip_known=False,
            off_hours=True,
            failed_logins=5,
            mfa_used=False
        )
        assert score == 10

    def test_high_risk_failures_and_no_mfa(self):
        """Known IP, business hours, failures + no MFA → score 5."""
        score = compute_risk_score(
            ip_known=True,
            off_hours=False,
            failed_logins=5,
            mfa_used=False
        )
        assert score == 5

    def test_score_is_non_negative(self):
        """Score must never be negative."""
        score = compute_risk_score(
            ip_known=True,
            off_hours=False,
            failed_logins=0,
            mfa_used=True
        )
        assert score >= 0

    def test_score_does_not_exceed_maximum(self):
        """Score must never exceed 10."""
        score = compute_risk_score(
            ip_known=False,
            off_hours=True,
            failed_logins=100,
            mfa_used=False
        )
        assert score <= 10


class TestGetDynamicLifetime:

    def test_score_0_returns_low_risk_lifetime(self):
        assert get_dynamic_lifetime(0) == 7200

    def test_score_3_returns_low_risk_lifetime(self):
        assert get_dynamic_lifetime(3) == 7200

    def test_score_4_returns_medium_risk_lifetime(self):
        assert get_dynamic_lifetime(4) == 3600

    def test_score_6_returns_medium_risk_lifetime(self):
        assert get_dynamic_lifetime(6) == 3600

    def test_score_7_returns_high_risk_lifetime(self):
        assert get_dynamic_lifetime(7) == 900

    def test_score_10_returns_high_risk_lifetime(self):
        assert get_dynamic_lifetime(10) == 900


class TestEndToEnd:
    """
    End-to-end validation of the three scenarios from Report 3 live testing.
    """

    def test_live_scenario_low_risk(self):
        """Reproduces the live low-risk scenario: score=2, lifetime=7200s."""
        score = compute_risk_score(
            ip_known=True,
            off_hours=True,   # test ran at 20:03 UTC, outside business hours
            failed_logins=0,
            mfa_used=True
        )
        assert score == 2
        assert get_dynamic_lifetime(score) == 7200

    def test_live_scenario_medium_risk(self):
        """Reproduces the live medium-risk scenario: score=5, lifetime=3600s."""
        score = compute_risk_score(
            ip_known=False,
            off_hours=True,
            failed_logins=0,
            mfa_used=True
        )
        assert score == 5
        assert get_dynamic_lifetime(score) == 3600

    def test_live_scenario_high_risk(self):
        """Reproduces the live high-risk scenario: score=10, lifetime=900s."""
        score = compute_risk_score(
            ip_known=False,
            off_hours=True,
            failed_logins=5,
            mfa_used=False
        )
        assert score == 10
        assert get_dynamic_lifetime(score) == 900
