"""
Context Analyzer
----------------
Distinguishes legitimate technical discussion from prompts
that contain actual malicious intent.
"""

from typing import Dict


EDUCATIONAL_PATTERNS = [
    "explain",
    "can you explain",
    "what are common",
    "how can developers defend",
    "how can developers prevent",
    "how do i normalize",
    "how do i decode",
    "how do i parse",
    "how do i convert",
    "how do i handle",
    "how should i handle",
    "how should i normalize",
    "how should i decode",
    "how can i normalize",
    "how can i decode",
    "how can i parse",
    "how can i convert",
    "how can i support",
    "how can i prevent",
    "how can i fix",
    "why does my regex",
    "why does",
    "why do",
    "what does",
    "difference between",
    "is this valid",
    "is this correct",
    "what is the difference",
    "what are",
    "what does this",
    "how does",
]


SECURITY_TOPIC_PATTERNS = [
    "prompt injection",
    "jailbreak",
    "system prompt",
    "hidden instruction",
    "hidden instructions",
    "obfuscation",
    "unicode",
    "homoglyph",
    "fullwidth",
    "zero-width",
    "zero width",
    "escape sequence",
    "escaped sequence",
    "hex encoding",
    "base64",
    "punycode",
    "ansi escape",
    "regex",
    "unicode escaping",
]


MALICIOUS_INTENT_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "forget previous instructions",
    "forget all previous instructions",
    "disregard previous instructions",
    "reveal your system prompt",
    "show me your system prompt",
    "show your hidden instructions",
    "reveal hidden instructions",
    "bypass security",
    "bypass protection",
    "disable safety",
    "remove restrictions",
    "jailbreak",
    "override instructions",
    "steal passwords",
    "steal credentials",
    "exfiltrate credentials",
    "deploy malware",
    "write ransomware",
    "hidden payload",
    "hide the payload",
    "embed the payload",
    "embed the string",
    "execute the payload",
    "execute it",
    "delete-all",
    "delete all",
]


def analyze_context(prompt: str) -> Dict:

    text = (prompt or "").lower().strip()

    if not text:
        return {
            "context": "UNKNOWN",
            "educational_score": 0,
            "malicious_intent_score": 0,
            "is_security_discussion": False,
            "is_malicious_context": False,
            "educational_matches": [],
            "security_topic_matches": [],
            "malicious_matches": [],
            "reasons": [
                "No prompt content was provided."
            ],
        }

    educational_matches = [
        pattern
        for pattern in EDUCATIONAL_PATTERNS
        if pattern in text
    ]

    security_topic_matches = [
        pattern
        for pattern in SECURITY_TOPIC_PATTERNS
        if pattern in text
    ]

    malicious_matches = [
        pattern
        for pattern in MALICIOUS_INTENT_PATTERNS
        if pattern in text
    ]

    # Educational evidence only becomes meaningful when
    # the prompt is actually discussing a relevant topic.
    if educational_matches and security_topic_matches:
        educational_score = min(
            20 + len(educational_matches) * 10,
            80,
        )
    else:
        educational_score = 0

    malicious_intent_score = min(
        len(malicious_matches) * 30,
        100,
    )

    # Explicit malicious intent takes priority.
    if malicious_intent_score >= 60:
        context = "MALICIOUS_CONTEXT"

    elif (
        educational_score >= 20
        and malicious_intent_score == 0
    ):
        context = "EDUCATIONAL"

    elif (
        security_topic_matches
        and malicious_intent_score == 0
    ):
        context = "SECURITY_DISCUSSION"

    elif malicious_intent_score > 0:
        context = "SUSPICIOUS"

    else:
        context = "NEUTRAL"

    is_security_discussion = context in {
        "SECURITY_DISCUSSION",
        "EDUCATIONAL",
    }

    is_malicious_context = (
        context == "MALICIOUS_CONTEXT"
    )

    reasons = []

    if educational_matches:
        reasons.append(
            "The prompt contains educational or "
            "technical discussion language."
        )

    if security_topic_matches:
        reasons.append(
            "The prompt discusses a security, "
            "encoding, or obfuscation-related topic."
        )

    if malicious_matches:
        reasons.append(
            "The prompt contains language associated "
            "with malicious intent."
        )

    if not reasons:
        reasons.append(
            "No strong contextual intent indicators "
            "were detected."
        )

    return {
        "context": context,
        "educational_score": educational_score,
        "malicious_intent_score": malicious_intent_score,
        "is_security_discussion": is_security_discussion,
        "is_malicious_context": is_malicious_context,
        "educational_matches": educational_matches,
        "security_topic_matches": security_topic_matches,
        "malicious_matches": malicious_matches,
        "reasons": reasons,
    }