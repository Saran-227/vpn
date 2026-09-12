from typing import List, Dict, Any

from app.models.schemas import SecurityFinding


# ---------------------------------------------------------
# Risk-level thresholds
# ---------------------------------------------------------

RISK_LEVELS = {
    "LOW": (0, 24),
    "MEDIUM": (25, 49),
    "HIGH": (50, 74),
    "CRITICAL": (75, 100),
}


# ---------------------------------------------------------
# Score weights
# ---------------------------------------------------------

RULE_WEIGHT = 0.70
ANOMALY_WEIGHT = 0.30


# ---------------------------------------------------------
# Calculate rule score
# ---------------------------------------------------------

def calculate_rule_score(
    findings: List[SecurityFinding]
) -> int:
    """
    Calculate the score contributed by rule-based findings.

    The score is capped at 100.
    """

    total_score = sum(
        finding.score
        for finding in findings
    )

    return min(total_score, 100)


# ---------------------------------------------------------
# Calculate final risk score
# ---------------------------------------------------------

def calculate_risk_score(
    findings: List[SecurityFinding],
    anomaly_score: int
) -> int:
    """
    Combine rule-based findings and anomaly score
    into one final risk score.

    Rule findings contribute 70%.
    Anomaly detection contributes 30%.

    Final score is always between 0 and 100.
    """

    rule_score = calculate_rule_score(findings)

    # Make sure anomaly score stays in a valid range.
    anomaly_score = max(0, min(anomaly_score, 100))

    weighted_rule_score = rule_score * RULE_WEIGHT
    weighted_anomaly_score = anomaly_score * ANOMALY_WEIGHT

    final_score = (
        weighted_rule_score
        + weighted_anomaly_score
    )

    return round(min(max(final_score, 0), 100))


# ---------------------------------------------------------
# Determine risk level
# ---------------------------------------------------------

def determine_risk_level(score: int) -> str:
    """
    Convert a numerical risk score into a risk level.
    """

    for level, (minimum, maximum) in RISK_LEVELS.items():

        if minimum <= score <= maximum:
            return level

    # Safety fallback.
    if score < 0:
        return "LOW"

    return "CRITICAL"


# ---------------------------------------------------------
# Generate score explanation
# ---------------------------------------------------------

def generate_score_explanation(
    findings: List[SecurityFinding],
    anomaly_score: int,
    final_score: int,
    risk_level: str
) -> str:
    """
    Generate a human-readable explanation of how
    the final risk score was produced.
    """

    rule_score = calculate_rule_score(findings)

    if not findings and anomaly_score == 0:
        return (
            "No significant security indicators or "
            "anomalous behavior were detected."
        )

    explanation_parts = [
        f"Rule-based score: {rule_score}/100.",
        f"Anomaly score: {anomaly_score}/100.",
        f"Final weighted risk score: {final_score}/100.",
        f"Risk level: {risk_level}."
    ]

    if findings:
        explanation_parts.append(
            f"{len(findings)} rule-based finding(s) "
            "contributed to the assessment."
        )

    if anomaly_score > 0:
        explanation_parts.append(
            "Anomalous behavioral indicators "
            "also contributed to the assessment."
        )

    return " ".join(explanation_parts)


# ---------------------------------------------------------
# Complete risk assessment
# ---------------------------------------------------------

def assess_risk(
    findings: List[SecurityFinding],
    anomaly_score: int
) -> Dict[str, Any]:
    """
    Calculate the complete risk assessment.

    Returns:
        Dictionary containing:
            - rule score
            - anomaly score
            - final score
            - risk level
            - explanation
    """

    rule_score = calculate_rule_score(findings)

    final_score = calculate_risk_score(
        findings,
        anomaly_score
    )

    risk_level = determine_risk_level(final_score)

    explanation = generate_score_explanation(
        findings,
        anomaly_score,
        final_score,
        risk_level
    )

    return {
        "rule_score": rule_score,
        "anomaly_score": anomaly_score,
        "risk_score": final_score,
        "risk_level": risk_level,
        "explanation": explanation
    }