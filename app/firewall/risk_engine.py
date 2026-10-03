def calculate_risk_score(detection_result):
    """
    Calculate a risk score from 0 to 100
    based on the type and number of detected patterns.
    """

    matched_patterns = detection_result["matched_patterns"]

    # No suspicious patterns
    if not matched_patterns:
        return {
            "risk_score": 0,
            "severity": "LOW",
            "action": "ALLOW"
        }

    risk_score = 0

    for pattern in matched_patterns:

        # Instruction override
        if "ignore" in pattern or "forget" in pattern:
            risk_score += 30

        # System prompt extraction
        elif "system prompt" in pattern:
            risk_score += 40

        # Security restriction bypass
        elif "bypass" in pattern or "unrestricted" in pattern:
            risk_score += 35

        # Other suspicious instructions
        else:
            risk_score += 20

    # Keep score between 0 and 100
    risk_score = min(risk_score, 100)

    # Determine severity and action
    if risk_score < 30:
        severity = "LOW"
        action = "ALLOW"

    elif risk_score < 70:
        severity = "MEDIUM"
        action = "REVIEW"

    else:
        severity = "HIGH"
        action = "BLOCK"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "action": action
    }