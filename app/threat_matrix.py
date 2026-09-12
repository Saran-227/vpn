from typing import Dict, Any, List


# ---------------------------------------------------------
# Threat Matrix
# ---------------------------------------------------------

SEVERITY_LEVELS = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW"
]


def create_threat_matrix(
    findings: List[Dict[str, Any]],
    anomaly_indicators: List[Dict[str, Any]],
    risk_score: int,
    risk_level: str
) -> Dict[str, Any]:
    """
    Organize security findings and anomaly indicators
    into a severity-based threat matrix.

    This function DOES NOT calculate the risk score.

    The risk score is already calculated by risk_scorer.py.
    The threat matrix only organizes and summarizes
    the detected security indicators.
    """

    matrix = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": []
    }

    # -----------------------------------------------------
    # Add rule-based findings
    # -----------------------------------------------------

    for finding in findings:

        severity = str(
            finding.get("severity", "LOW")
        ).upper()

        if severity not in SEVERITY_LEVELS:
            severity = "LOW"

        matrix[severity].append(
            {
                "indicator": finding.get(
                    "indicator",
                    "UNKNOWN"
                ),
                "source": "rule_engine",
                "severity": severity,
                "score": finding.get(
                    "score",
                    0
                ),
                "reason": finding.get(
                    "reason",
                    ""
                )
            }
        )

    # -----------------------------------------------------
    # Add anomaly indicators
    # -----------------------------------------------------

    for indicator in anomaly_indicators:

        severity = str(
            indicator.get("severity", "LOW")
        ).upper()

        if severity not in SEVERITY_LEVELS:
            severity = "LOW"

        matrix[severity].append(
            {
                "indicator": indicator.get(
                    "indicator",
                    "UNKNOWN"
                ),
                "source": "anomaly_detector",
                "severity": severity,
                "score": None,
                "reason": indicator.get(
                    "reason",
                    ""
                )
            }
        )

    # -----------------------------------------------------
    # Count threats by severity
    # -----------------------------------------------------

    severity_counts = {
        level: len(matrix[level])
        for level in SEVERITY_LEVELS
    }

    total_findings = sum(
        severity_counts.values()
    )

    # -----------------------------------------------------
    # Final threat matrix
    # -----------------------------------------------------

    return {
        "overall_risk_score": risk_score,
        "overall_risk_level": risk_level,
        "total_indicators": total_findings,

        "severity_counts": severity_counts,

        "critical": matrix["CRITICAL"],
        "high": matrix["HIGH"],
        "medium": matrix["MEDIUM"],
        "low": matrix["LOW"]
    }
