import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

import pytest
from evaluator import evaluate, _count_by_severity, _compute_risk_score


def make_finding(severity, ftype="test_finding"):
    return {"type": ftype, "severity": severity, "detail": f"Test {severity} finding"}


class TestCountBySeverity:
    def test_empty(self):
        result = _count_by_severity([])
        assert result["CRITICAL"] == 0
        assert result["HIGH"] == 0

    def test_mixed(self):
        findings = [
            make_finding("CRITICAL"),
            make_finding("CRITICAL"),
            make_finding("HIGH"),
            make_finding("MEDIUM"),
            make_finding("LOW"),
        ]
        result = _count_by_severity(findings)
        assert result["CRITICAL"] == 2
        assert result["HIGH"] == 1
        assert result["MEDIUM"] == 1
        assert result["LOW"] == 1


class TestEvaluate:
    def test_pass_no_findings(self):
        result = evaluate([])
        assert result["passed"] is True
        assert result["exit_code"] == 0
        assert result["risk_score"] == 0

    def test_fail_on_critical(self):
        findings = [make_finding("CRITICAL")]
        result = evaluate(findings)
        assert result["passed"] is False
        assert result["exit_code"] == 1
        assert len(result["failure_reasons"]) > 0

    def test_fail_on_too_many_high(self):
        findings = [make_finding("HIGH") for _ in range(5)]
        result = evaluate(findings)
        assert result["passed"] is False

    def test_pass_below_threshold(self):
        findings = [make_finding("HIGH"), make_finding("HIGH")]
        result = evaluate(findings)
        assert result["passed"] is True

    def test_custom_threshold_strict(self):
        findings = [make_finding("HIGH")]
        result = evaluate(findings, thresholds={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 999, "LOW": 999})
        assert result["passed"] is False

    def test_custom_threshold_lenient(self):
        findings = [make_finding("CRITICAL")]
        result = evaluate(findings, thresholds={"CRITICAL": 5, "HIGH": 99, "MEDIUM": 999, "LOW": 999})
        assert result["passed"] is True

    def test_risk_score_increases_with_severity(self):
        low_result = evaluate([make_finding("LOW")])
        high_result = evaluate([make_finding("HIGH")])
        critical_result = evaluate([make_finding("CRITICAL")])
        assert low_result["risk_score"] < high_result["risk_score"] < critical_result["risk_score"]

    def test_owasp_enrichment(self):
        findings = [{"type": "no_https_redirect", "severity": "HIGH", "detail": "test"}]
        result = evaluate(findings)
        enriched = result["findings_by_severity"]["HIGH"]
        assert any("owasp_category" in f for f in enriched)

    def test_evaluated_at_present(self):
        result = evaluate([])
        assert "evaluated_at" in result
        assert result["evaluated_at"].endswith("Z")


class TestRiskScore:
    def test_zero_for_empty(self):
        assert _compute_risk_score({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}) == 0

    def test_capped_at_100(self):
        score = _compute_risk_score({"CRITICAL": 100, "HIGH": 100, "MEDIUM": 100, "LOW": 100})
        assert score == 100