from datetime import datetime, timezone
from typing import Dict, Any

from app.input_adapter import normalize_features
from app.feature_validator import validate_features
from app.rule_engine import evaluate_rules
from app.anomaly_detector import detect_anomalies
from app.risk_scorer import assess_risk
from app.output_formatter import format_assessment
from app.threat_matrix import create_threat_matrix


class SecurityAssessmentEngine:
    """
    Main entry point for the Security Assessment Engine.

    The engine coordinates:

        1. Feature normalization
        2. Feature validation
        3. Rule-based detection
        4. Anomaly detection
        5. Risk scoring
        6. Threat matrix generation
        7. Final assessment generation
    """

    def __init__(self):
        self.name = "IPsec VPN Security Assessment Engine"
        self.version = "1.0.0"

    def assess(self, raw_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess a set of network/flow features.

        Args:
            raw_features: Raw or standardized network features.

        Returns:
            A JSON-serializable security assessment.

        Raises:
            TypeError: If raw_features is not a dictionary.
            ValueError: If the supplied features are invalid.
        """

        # STEP 1: Normalize input
        features = normalize_features(raw_features)

        # STEP 2: Validate normalized features
        validation_errors = validate_features(features)
        if validation_errors:
            raise ValueError(
                "Feature validation failed: " + "; ".join(validation_errors)
            )

        # STEP 3: Run rule-based security checks
        findings = evaluate_rules(features)

        # STEP 4: Run anomaly detection
        anomaly_result = detect_anomalies(features)
        anomaly_score = anomaly_result["anomaly_score"]
        anomaly_detected = anomaly_result["anomaly_detected"]
        anomaly_indicators = anomaly_result["indicators"]

        # STEP 5: Calculate overall risk
        risk_result = assess_risk(findings, anomaly_score)

        # STEP 6: Serialize findings and anomaly indicators
        finding_results = [
            {
                "indicator": f.indicator,
                "severity": f.severity,
                "score": f.score,
                "reason": f.reason,
            }
            for f in findings
        ]

        anomaly_results = [
            {
                "indicator": i["indicator"],
                "severity": i["severity"],
                "reason": i["reason"],
            }
            for i in anomaly_indicators
        ]

        # STEP 7: Generate threat matrix
        threat_matrix = create_threat_matrix(
            findings=finding_results,
            anomaly_indicators=anomaly_indicators,
            risk_score=risk_result["risk_score"],
            risk_level=risk_result["risk_level"],
        )

        # STEP 8: Generate timestamp
        timestamp = datetime.now(timezone.utc).isoformat()

        # STEP 9: Generate final summary
        summary = self._generate_summary(
            risk_result["risk_level"], finding_results, anomaly_detected
        )

        # STEP 10: Return formatted assessment
        return format_assessment(
            {
                "engine": {"name": self.name, "version": self.version},
                "timestamp": timestamp,
                "risk_score": risk_result["risk_score"],
                "risk_level": risk_result["risk_level"],
                "rule_score": risk_result["rule_score"],
                "anomaly_score": risk_result["anomaly_score"],
                "anomaly_detected": anomaly_detected,
                "findings": finding_results,
                "anomaly_indicators": anomaly_results,
                "threat_matrix": threat_matrix,
                "score_explanation": risk_result["explanation"],
                "summary": summary,
            }
        )

    @staticmethod
    def _generate_summary(
        risk_level: str, findings: list, anomaly_detected: bool
    ) -> str:
        """Generate a short human-readable summary."""

        if risk_level == "LOW" and not findings and not anomaly_detected:
            return (
                "No significant security indicators or "
                "anomalous behavior were detected."
            )

        if risk_level == "MEDIUM":
            return (
                "Some potentially unusual network behavior "
                "was detected and should be reviewed."
            )

        if risk_level == "HIGH":
            return (
                "Significant security indicators or anomalous "
                "network behavior were detected."
            )

        if risk_level == "CRITICAL":
            return (
                "Critical security indicators were detected. "
                "Immediate investigation is recommended."
            )

        return "The traffic requires further security assessment."
