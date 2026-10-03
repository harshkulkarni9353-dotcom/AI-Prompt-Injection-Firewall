import pandas as pd
from pathlib import Path


INPUT_FILE = (
    Path(__file__).resolve().parent
    / "processed"
    / "api_full_evaluation_results.csv"
)


def main():

    df = pd.read_csv(INPUT_FILE)

    errors = df[
        df["expected"] != df["predicted"]
    ].copy()

    false_positives = errors[
        (errors["expected"] == "SAFE") &
        (errors["predicted"] == "MALICIOUS")
    ]

    false_negatives = errors[
        (errors["expected"] == "MALICIOUS") &
        (errors["predicted"] == "SAFE")
    ]

    print("=" * 80)
    print("API ERROR ANALYSIS")
    print("=" * 80)

    print(f"\nTotal errors: {len(errors)}")
    print(f"False positives: {len(false_positives)}")
    print(f"False negatives: {len(false_negatives)}")

    print("\n" + "=" * 80)
    print("FALSE POSITIVES - SAFE → MALICIOUS")
    print("=" * 80)

    for _, row in false_positives.iterrows():

        print(f"\nTest ID: {row['test_id']}")
        print(f"Category: {row['category']}")
        print(f"Firewall category: {row['firewall_category']}")
        print(f"Detection source: {row['detection_source']}")
        print(f"ML prediction: {row['ml_prediction']}")
        print(f"ML confidence: {row['ml_confidence']}")
        print(f"Risk score: {row['risk_score']}")
        print(f"Severity: {row['severity']}")
        print(f"Action: {row['action']}")
        print(f"Obfuscation: {row['obfuscation_detected']}")
        print(f"Prompt: {row['prompt']}")

    print("\n" + "=" * 80)
    print("FALSE NEGATIVES - MALICIOUS → SAFE")
    print("=" * 80)

    for _, row in false_negatives.iterrows():

        print(f"\nTest ID: {row['test_id']}")
        print(f"Category: {row['category']}")
        print(f"Firewall category: {row['firewall_category']}")
        print(f"Detection source: {row['detection_source']}")
        print(f"ML prediction: {row['ml_prediction']}")
        print(f"ML confidence: {row['ml_confidence']}")
        print(f"Risk score: {row['risk_score']}")
        print(f"Severity: {row['severity']}")
        print(f"Action: {row['action']}")
        print(f"Obfuscation: {row['obfuscation_detected']}")
        print(f"Prompt: {row['prompt']}")

    print("\n" + "=" * 80)
    print("ERRORS BY CATEGORY")
    print("=" * 80)

    print(
        errors["category"]
        .fillna("UNKNOWN")
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 80)
    print("ERRORS BY DETECTION SOURCE")
    print("=" * 80)

    print(
        errors["detection_source"]
        .fillna("UNKNOWN")
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 80)
    print("ERROR ANALYSIS COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()