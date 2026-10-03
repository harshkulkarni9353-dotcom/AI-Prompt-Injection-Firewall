import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent)
)

import pandas as pd

from app.firewall.context_analyzer import analyze_context


INPUT_FILE = (
    Path(__file__).resolve().parent.parent
    / "dataset"
    / "processed"
    / "api_full_evaluation_results.csv"
)


def main():

    df = pd.read_csv(INPUT_FILE)

    errors = df[
        df["expected"] != df["predicted"]
    ].copy()

    print("=" * 80)
    print("CONTEXT ANALYZER - REAL API ERROR ANALYSIS")
    print("=" * 80)

    print(f"\nTotal API errors: {len(errors)}")

    context_results = []

    for _, row in errors.iterrows():

        result = analyze_context(
            str(row["prompt"])
        )

        context_results.append({
            "test_id": row["test_id"],
            "expected": row["expected"],
            "predicted": row["predicted"],
            "original_action": row["action"],
            "original_detection_source": row[
                "detection_source"
            ],
            "original_risk": row["risk_score"],
            "context": result["context"],
            "educational_score": result[
                "educational_score"
            ],
            "malicious_intent_score": result[
                "malicious_intent_score"
            ],
            "security_discussion": result[
                "is_security_discussion"
            ],
            "malicious_context": result[
                "is_malicious_context"
            ],
            "prompt": row["prompt"],
        })

    results = pd.DataFrame(context_results)

    print("\n" + "=" * 80)
    print("CONTEXT DISTRIBUTION")
    print("=" * 80)

    print(
        results["context"]
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 80)
    print("FALSE POSITIVES WITH CONTEXT")
    print("=" * 80)

    false_positives = results[
        (results["expected"] == "SAFE") &
        (results["predicted"] == "MALICIOUS")
    ]

    print(
        false_positives[
            [
                "test_id",
                "context",
                "educational_score",
                "malicious_intent_score",
                "original_risk",
                "original_action",
            ]
        ].to_string(index=False)
    )

    print("\n" + "=" * 80)
    print("FALSE NEGATIVES WITH CONTEXT")
    print("=" * 80)

    false_negatives = results[
        (results["expected"] == "MALICIOUS") &
        (results["predicted"] == "SAFE")
    ]

    print(
        false_negatives[
            [
                "test_id",
                "context",
                "educational_score",
                "malicious_intent_score",
                "original_risk",
                "original_action",
            ]
        ].to_string(index=False)
    )

    print("\n" + "=" * 80)
    print("DETAILED FALSE NEGATIVE ANALYSIS")
    print("=" * 80)

    for _, row in false_negatives.iterrows():

        print(f"\nTest ID: {row['test_id']}")
        print(f"Context: {row['context']}")
        print(
            f"Educational score: "
            f"{row['educational_score']}"
        )
        print(
            f"Malicious score: "
            f"{row['malicious_intent_score']}"
        )
        print(f"Prompt: {row['prompt']}")

    output_file = (
        Path(__file__).resolve().parent
        / "context_error_analysis.csv"
    )

    results.to_csv(
        output_file,
        index=False
    )

    print("\n" + "=" * 80)
    print("RESULT SAVED")
    print("=" * 80)

    print(output_file)


if __name__ == "__main__":
    main()