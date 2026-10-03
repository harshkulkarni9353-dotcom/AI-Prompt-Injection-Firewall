"""
Risk and Policy Engine
----------------------
Converts detection evidence into a consistent security decision.

Decision levels:
    ALLOW
    REVIEW
    BLOCK
"""

from typing import Dict, Any


# ============================================================
# POLICY THRESHOLDS
# ============================================================

ALLOW_THRESHOLD = 30
REVIEW_THRESHOLD = 70
BLOCK_THRESHOLD = 70


# ============================================================
# RISK CONTRIBUTION WEIGHTS
# ============================================================

RULE_WEIGHTS = {
    "PROMPT_INJECTION": 50,
    "SYSTEM_PROMPT_EXTRACTION": 60,
    "JAILBREAK": 60,
    "ROLE_MANIPULATION": 50,
    "HARMFUL INTENT": 75,
    "CYBER ABUSE": 75,
    "DATA EXFILTRATION": 75,
    "OBFUSCATION": 30,
}


# ============================================================
# POLICY ENGINE
# ============================================================

def evaluate_policy(
    rule_detected: bool,
    ml_detected: bool,
    ml_confidence: float,
    obfuscation_detected: bool,
    threat_category: str,
    obfuscation_indicators=None,
) -> Dict[str, Any]:

    if obfuscation_indicators is None:
        obfuscation_indicators = []


    # --------------------------------------------------------
    # NORMALIZE VALUES
    # --------------------------------------------------------

    ml_confidence = max(
        0.0,
        min(float(ml_confidence), 100.0)
    )

    threat_category = (
        threat_category
        or "BENIGN"
    )


    # --------------------------------------------------------
    # INDIVIDUAL RISK CONTRIBUTIONS
    # --------------------------------------------------------

    rule_score = 0

    if rule_detected:

        rule_score = RULE_WEIGHTS.get(
            threat_category,
            50
        )


    ml_score = 0

    if ml_detected:

        ml_score = round(
            ml_confidence * 0.40
        )


    obfuscation_score = 0

    if obfuscation_detected:

        obfuscation_score = 30

        encoded_indicators = {
            "BASE64_SUSPICIOUS_CONTENT",
            "HEX_SUSPICIOUS_CONTENT",
            "ZERO_WIDTH_CHARACTERS",
            "UNICODE_HOMOGLYPH_INDICATOR",
            "CHARACTER_FRAGMENTATION",
            "ESCAPED_CHARACTER_SEQUENCE",
        }

        if any(
            indicator in encoded_indicators
            for indicator in obfuscation_indicators
        ):

            obfuscation_score += 15


    # --------------------------------------------------------
    # DETECTOR AGREEMENT BONUS
    # --------------------------------------------------------

    agreement_bonus = 0

    if rule_detected and ml_detected:

        agreement_bonus += 10

    if ml_detected and obfuscation_detected:

        agreement_bonus += 10


    # --------------------------------------------------------
    # CALCULATE RAW RISK SCORE
    # --------------------------------------------------------

    raw_score = (
        rule_score
        + ml_score
        + obfuscation_score
        + agreement_bonus
    )


    # --------------------------------------------------------
    # HIGH-RISK CATEGORY FLOOR
    # --------------------------------------------------------

    if threat_category in {
        "HARMFUL INTENT",
        "CYBER ABUSE",
        "DATA EXFILTRATION",
    }:

        raw_score = max(
            raw_score,
            80
        )


    # --------------------------------------------------------
    # OBFUSCATED MALICIOUS CONTENT FLOOR
    # --------------------------------------------------------

    if (
        ml_detected
        and obfuscation_detected
    ):

        raw_score = max(
            raw_score,
            80
        )


    risk_score = min(
        raw_score,
        100
    )


    # --------------------------------------------------------
    # MALICIOUS ENFORCEMENT FLOOR
    # --------------------------------------------------------
    #
    # A malicious ML classification should never silently
    # become ALLOW.
    #
    # >= 90% ML confidence -> minimum HIGH / BLOCK
    # <  90% ML confidence -> minimum MEDIUM / REVIEW
    #
    # --------------------------------------------------------

    if ml_detected:

        if ml_confidence >= 90:

            risk_score = max(
                risk_score,
                70
            )

        else:

            risk_score = max(
                risk_score,
                30
            )


    # --------------------------------------------------------
    # SEVERITY
    # --------------------------------------------------------

    if risk_score >= 80:

        severity = "CRITICAL"

    elif risk_score >= 70:

        severity = "HIGH"

    elif risk_score >= 30:

        severity = "MEDIUM"

    else:

        severity = "LOW"


    # --------------------------------------------------------
    # POLICY ACTION
    # --------------------------------------------------------

    if risk_score >= BLOCK_THRESHOLD:

        action = "BLOCK"

    elif risk_score >= ALLOW_THRESHOLD:

        action = "REVIEW"

    else:

        action = "ALLOW"


    # --------------------------------------------------------
    # POLICY REASONS
    # --------------------------------------------------------

    reasons = []


    if rule_detected:

        reasons.append(
            f"Rule engine detected "
            f"{threat_category}."
        )


    if ml_detected:

        reasons.append(
            f"ML detector classified the prompt "
            f"as malicious with "
            f"{ml_confidence:.2f}% confidence."
        )


    if obfuscation_detected:

        reasons.append(
            "Obfuscation or hidden-content "
            "indicators were detected."
        )


    if rule_detected and ml_detected:

        reasons.append(
            "Rule and ML detectors independently "
            "identified suspicious behavior."
        )


    if ml_detected and obfuscation_detected:

        reasons.append(
            "ML detection agrees with the "
            "obfuscation analysis."
        )


    if not reasons:

        reasons.append(
            "No significant security indicators "
            "were detected."
        )


    # --------------------------------------------------------
    # FINAL POLICY RESULT
    # --------------------------------------------------------

    return {

        "risk_score":
            risk_score,

        "severity":
            severity,

        "action":
            action,

        "risk_breakdown": {

            "rule_score":
                rule_score,

            "ml_score":
                ml_score,

            "obfuscation_score":
                obfuscation_score,

            "agreement_bonus":
                agreement_bonus,
        },

        "policy": {

            "allow_threshold":
                ALLOW_THRESHOLD,

            "review_threshold":
                REVIEW_THRESHOLD,

            "block_threshold":
                BLOCK_THRESHOLD,
        },

        "reasons":
            reasons,
    }