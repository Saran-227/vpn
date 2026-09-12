from app.risk_scorer import (
    calculate_rule_score,
    calculate_risk_score,
    determine_risk_level,
    generate_score_explanation,
    assess_risk
)

from app.models.schemas import SecurityFinding


def create_finding(score, severity="HIGH"):
    return SecurityFinding(
        indicator="TEST_INDICATOR",
        severity=severity,
        score=score,
        reason="Test finding"
    )


def test_rule_score_with_no_findings():
    score = calculate_rule_score([])

    assert score == 0


def test_rule_score_with_findings():
    findings = [
        create_finding(25),
        create_finding(20)
    ]

    score = calculate_rule_score(findings)

    assert score == 45


def test_rule_score_is_capped_at_100():
    findings = [
        create_finding(60),
        create_finding(60)
    ]

    score = calculate_rule_score(findings)

    assert score == 100


def test_risk_score_with_no_risk():
    score = calculate_risk_score([], 0)

    assert score == 0


def test_risk_score_combines_rule_and_anomaly_scores():
    findings = [
        create_finding(80)
    ]

    score = calculate_risk_score(
        findings,
        50
    )

    expected = round(
        (80 * 0.70) + (50 * 0.30)
    )

    assert score == expected


def test_risk_score_is_capped_at_100():
    findings = [
        create_finding(100)
    ]

    score = calculate_risk_score(
        findings,
        100
    )

    assert score == 100


def test_negative_anomaly_score_is_handled():
    score = calculate_risk_score(
        [],
        -50
    )

    assert score == 0


def test_anomaly_score_above_100_is_handled():
    score = calculate_risk_score(
        [],
        150
    )

    assert score == 30


def test_low_risk_level():
    assert determine_risk_level(10) == "LOW"


def test_medium_risk_level():
    assert determine_risk_level(30) == "MEDIUM"


def test_high_risk_level():
    assert determine_risk_level(60) == "HIGH"


def test_critical_risk_level():
    assert determine_risk_level(80) == "CRITICAL"


def test_risk_level_boundaries():
    assert determine_risk_level(24) == "LOW"
    assert determine_risk_level(25) == "MEDIUM"
    assert determine_risk_level(49) == "MEDIUM"
    assert determine_risk_level(50) == "HIGH"
    assert determine_risk_level(74) == "HIGH"
    assert determine_risk_level(75) == "CRITICAL"


def test_score_explanation_for_no_findings():
    explanation = generate_score_explanation(
        [],
        0,
        0,
        "LOW"
    )

    assert "No significant security indicators" in explanation


def test_score_explanation_contains_scores():
    findings = [
        create_finding(50)
    ]

    explanation = generate_score_explanation(
        findings,
        40,
        47,
        "MEDIUM"
    )

    assert "Rule-based score: 50/100." in explanation
    assert "Anomaly score: 40/100." in explanation
    assert "Final weighted risk score: 47/100." in explanation
    assert "Risk level: MEDIUM." in explanation


def test_assess_risk_returns_complete_result():
    findings = [
        create_finding(50)
    ]

    result = assess_risk(
        findings,
        40
    )

    assert "rule_score" in result
    assert "anomaly_score" in result
    assert "risk_score" in result
    assert "risk_level" in result
    assert "explanation" in result


def test_assess_risk_calculates_correct_values():
    findings = [
        create_finding(50)
    ]

    result = assess_risk(
        findings,
        40
    )

    assert result["rule_score"] == 50
    assert result["anomaly_score"] == 40
    assert result["risk_score"] == 47
    assert result["risk_level"] == "MEDIUM"