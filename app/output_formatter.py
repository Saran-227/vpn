import json
from typing import Dict, Any


def format_assessment(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """
    Prepare the security assessment in a clean,
    consistent structure.

    The returned dictionary is JSON serializable.
    """

    return {
        "engine": assessment.get("engine", {}),
        "timestamp": assessment.get("timestamp"),
        "risk_score": assessment.get("risk_score", 0),
        "risk_level": assessment.get("risk_level", "LOW"),
        "rule_score": assessment.get("rule_score", 0),
        "anomaly_score": assessment.get("anomaly_score", 0),
        "anomaly_detected": assessment.get("anomaly_detected", False),
        "findings": assessment.get("findings", []),
        "anomaly_indicators": assessment.get("anomaly_indicators", []),
        "threat_matrix": assessment.get("threat_matrix", {}),
        "score_explanation": assessment.get("score_explanation", ""),
        "summary": assessment.get("summary", ""),
    }


def assessment_to_json(assessment: Dict[str, Any], indent: int = 4) -> str:
    """
    Convert a security assessment dictionary into a JSON string.

    Args:
        assessment: Security assessment dictionary.
        indent: Number of spaces used for JSON formatting.

    Returns:
        JSON formatted string.
    """

    return json.dumps(
        format_assessment(assessment),
        indent=indent,
        ensure_ascii=False,
    )
