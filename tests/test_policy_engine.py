import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent)
)

from app.firewall.policy_engine import evaluate_policy


test_cases = [

    {
        "name": "BENIGN PROMPT",
        "rule_detected": False,
        "ml_detected": False,
        "ml_confidence": 78.99,
        "obfuscation_detected": False,
        "threat_category": "BENIGN",
        "obfuscation_indicators": [],
    },

    {
        "name": "DIRECT PROMPT INJECTION",
        "rule_detected": True,
        "ml_detected": True,
        "ml_confidence": 98.82,
        "obfuscation_detected": False,
        "threat_category": "PROMPT_INJECTION",
        "obfuscation_indicators": [],
    },

    {
        "name": "BASE64 OBFUSCATION",
        "rule_detected": False,
        "ml_detected": True,
        "ml_confidence": 83.52,
        "obfuscation_detected": True,
        "threat_category": "OBFUSCATION",
        "obfuscation_indicators": [
            "BASE64_SUSPICIOUS_CONTENT"
        ],
    },

    {
        "name": "SYSTEM PROMPT EXTRACTION",
        "rule_detected": True,
        "ml_detected": True,
        "ml_confidence": 95.0,
        "obfuscation_detected": False,
        "threat_category": "SYSTEM_PROMPT_EXTRACTION",
        "obfuscation_indicators": [],
    },

    {
        "name": "CYBER ABUSE",
        "rule_detected": True,
        "ml_detected": True,
        "ml_confidence": 94.0,
        "obfuscation_detected": False,
        "threat_category": "CYBER ABUSE",
        "obfuscation_indicators": [],
    },
]


print("=" * 70)
print("AI PROMPT INJECTION FIREWALL")
print("RISK & POLICY ENGINE TEST")
print("=" * 70)


for case in test_cases:

    result = evaluate_policy(
        rule_detected=case["rule_detected"],
        ml_detected=case["ml_detected"],
        ml_confidence=case["ml_confidence"],
        obfuscation_detected=case["obfuscation_detected"],
        threat_category=case["threat_category"],
        obfuscation_indicators=case["obfuscation_indicators"],
    )

    print()
    print(case["name"])
    print("-" * 70)

    print("Risk Score :", result["risk_score"])
    print("Severity   :", result["severity"])
    print("Action     :", result["action"])

    print()
    print("Risk Breakdown:")

    for key, value in result["risk_breakdown"].items():
        print(f"  {key:<20}: {value}")

    print()
    print("Policy Reasons:")

    for reason in result["reasons"]:
        print("  -", reason)


print()
print("=" * 70)
print("POLICY ENGINE TEST COMPLETED")
print("=" * 70)