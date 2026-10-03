import joblib

from app.firewall.detector import detect_prompt_injection
from app.firewall.obfuscation import detect_obfuscation
from app.firewall.context_analyzer import analyze_context
from app.firewall.policy_engine import evaluate_policy


MODEL_PATH = "dataset/prompt_injection_model_v2.pkl"

saved = joblib.load(MODEL_PATH)
model = saved["model"]
vectorizer = saved["vectorizer"]


def hybrid_detect(prompt: str):

    # ---------------------------------------------------------
    # 1. RULE-BASED DETECTION
    # ---------------------------------------------------------
    rule_result = detect_prompt_injection(prompt)
    rule_malicious = rule_result.get("is_malicious", False)

    # ---------------------------------------------------------
    # 2. MACHINE LEARNING DETECTION
    # ---------------------------------------------------------
    prompt_vector = vectorizer.transform([prompt])

    ml_prediction = model.predict(prompt_vector)[0]

    probabilities = model.predict_proba(prompt_vector)[0]

    ml_confidence = round(
        float(max(probabilities) * 100),
        2
    )

    ml_malicious = ml_prediction == "MALICIOUS"

    # ---------------------------------------------------------
    # 3. OBFUSCATION DETECTION
    # ---------------------------------------------------------
    obfuscation_result = detect_obfuscation(prompt)

    obfuscated = obfuscation_result.get(
        "is_obfuscated",
        False
    )

    obfuscation_indicators = obfuscation_result.get(
        "indicators",
        []
    )

    # ---------------------------------------------------------
    # 4. CONTEXT ANALYSIS
    # ---------------------------------------------------------
    context_result = analyze_context(prompt)

    context = context_result.get(
        "context",
        "UNKNOWN"
    )

    # ---------------------------------------------------------
    # 5. CONTEXT-AWARE OBFUSCATION DECISION
    #
    # Legitimate educational/security discussions may contain
    # Unicode, Base64, hex, regex, escaping, etc.
    #
    # We therefore keep the raw obfuscation detection for
    # explainability, but don't automatically treat it as
    # malicious when the context is clearly educational.
    # ---------------------------------------------------------

    legitimate_security_context = context in {
        "EDUCATIONAL",
        "SECURITY_DISCUSSION",
    }

    malicious_context = context in {
        "MALICIOUS_CONTEXT",
        "SUSPICIOUS",
    }

    effective_obfuscation = obfuscated

    if (
        obfuscated
        and legitimate_security_context
        and not rule_malicious
        and not ml_malicious
    ):
        effective_obfuscation = False

    # ---------------------------------------------------------
    # 6. THREAT CATEGORY
    # ---------------------------------------------------------

    threat_category = rule_result.get(
        "threat_category"
    )

    if not threat_category:

        if effective_obfuscation:
            threat_category = "OBFUSCATION"

        elif ml_malicious:
            threat_category = "PROMPT_INJECTION"

        elif context in {
            "EDUCATIONAL",
            "SECURITY_DISCUSSION",
        }:
            threat_category = "BENIGN"

        else:
            threat_category = "BENIGN"

    # ---------------------------------------------------------
    # 7. THREAT CATEGORIES
    # ---------------------------------------------------------

    threat_categories = list(
        rule_result.get(
            "threat_categories",
            []
        )
    )

    if obfuscated and "OBFUSCATION" not in threat_categories:
        threat_categories.append(
            "OBFUSCATION"
        )

    # ---------------------------------------------------------
    # 8. POLICY ENGINE
    #
    # IMPORTANT:
    # Pass effective_obfuscation instead of raw obfuscation.
    # This prevents legitimate technical discussions from
    # receiving a malicious risk score merely because they
    # contain Unicode/encoding indicators.
    # ---------------------------------------------------------

    policy_result = evaluate_policy(
        rule_detected=rule_malicious,
        ml_detected=ml_malicious,
        ml_confidence=ml_confidence,
        obfuscation_detected=effective_obfuscation,
        threat_category=threat_category,
        obfuscation_indicators=obfuscation_indicators,
    )

    # ---------------------------------------------------------
    # 9. DETECTION SOURCES
    # ---------------------------------------------------------

    sources = []

    if rule_malicious:
        sources.append("RULE")

    if ml_malicious:
        sources.append("ML")

    if effective_obfuscation:
        sources.append("OBFUSCATION")

    detection_source = (
        " + ".join(sources)
        if sources
        else "NONE"
    )

    # ---------------------------------------------------------
    # 10. FINAL MALICIOUS DECISION
    # ---------------------------------------------------------

    is_malicious = (
        rule_malicious
        or ml_malicious
        or effective_obfuscation
    )

    # ---------------------------------------------------------
    # 11. EXPLANATION / REASONS
    # ---------------------------------------------------------

    reasons = []

    reasons.extend(
        rule_result.get(
            "reasons",
            []
        )
    )

    if ml_malicious:

        reasons.append(
            "The machine learning model classified "
            "the prompt as malicious."
        )

        if ml_confidence >= 90:

            reasons.append(
                "The ML model has high confidence "
                "in the malicious classification."
            )

    if obfuscated:

        reasons.append(
            "The prompt contains obfuscation or "
            "hidden-content indicators."
        )

        for indicator in obfuscation_indicators:

            reasons.append(
                f"Obfuscation technique detected: "
                f"{indicator}."
            )

    # ---------------------------------------------------------
    # CONTEXT EXPLANATION
    # ---------------------------------------------------------

    if context == "EDUCATIONAL":

        reasons.append(
            "The context analyzer identified the "
            "prompt as an educational or technical discussion."
        )

    elif context == "SECURITY_DISCUSSION":

        reasons.append(
            "The context analyzer identified the "
            "prompt as a legitimate security discussion."
        )

    elif context == "MALICIOUS_CONTEXT":

        reasons.append(
            "The context analyzer identified language "
            "associated with malicious intent."
        )

    elif context == "SUSPICIOUS":

        reasons.append(
            "The context analyzer identified suspicious "
            "intent indicators."
        )

    if (
        obfuscated
        and not effective_obfuscation
        and legitimate_security_context
    ):

        reasons.append(
            "Obfuscation indicators were observed, "
            "but the context appears educational or "
            "security-focused, so they were not treated "
            "as malicious by themselves."
        )

    reasons.extend(
        policy_result.get(
            "reasons",
            []
        )
    )

    reasons = list(
        dict.fromkeys(reasons)
    )

    # ---------------------------------------------------------
    # 12. FINAL RESULT
    # ---------------------------------------------------------

    return {

        "is_malicious": is_malicious,

        "threat_category": threat_category,

        "threat_categories": threat_categories,

        "detection_source": detection_source,

        "ml_prediction": ml_prediction,

        "ml_confidence": ml_confidence,

        # Raw obfuscation result
        "obfuscation_detected": obfuscated,

        "obfuscation_indicators": (
            obfuscation_indicators
        ),

        "decoded_content": (
            obfuscation_result.get(
                "decoded_content",
                []
            )
        ),

        # Context information
        "context": context,

        "context_analysis": context_result,

        "effective_obfuscation": (
            effective_obfuscation
        ),

        # Risk / policy
        "risk_score": policy_result[
            "risk_score"
        ],

        "severity": policy_result[
            "severity"
        ],

        "action": policy_result[
            "action"
        ],

        "risk_breakdown": policy_result[
            "risk_breakdown"
        ],

        "policy": policy_result[
            "policy"
        ],

        # Explanation
        "reasons": reasons,

        # Detailed detector outputs
        "matched_patterns": rule_result.get(
            "matched_patterns",
            []
        ),

        "rule_detection": rule_result,

        "obfuscation_detection": (
            obfuscation_result
        ),

        "context_detection": context_result,

        "policy_decision": policy_result,
    }