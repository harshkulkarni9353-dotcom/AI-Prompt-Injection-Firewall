import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time
import requests
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)


API_URL = "http://127.0.0.1:8000/analyze"

INPUT_FILE = (
    Path(__file__).resolve().parent
    / "processed"
    / "test.csv"
)

OUTPUT_FILE = (
    Path(__file__).resolve().parent
    / "processed"
    / "api_full_evaluation_results.csv"
)


def main():

    print("=" * 75)
    print("AI PROMPT INJECTION FIREWALL")
    print("FULL API EVALUATION - 804 HELD-OUT TEST SAMPLES")
    print("=" * 75)

    df = pd.read_csv(INPUT_FILE)

    print(f"\nLoaded samples: {len(df)}")
    print(f"Columns: {list(df.columns)}")

    results = []

    total_start = time.perf_counter()

    for index, row in df.iterrows():

        prompt = str(row["prompt"])
        expected = str(row["label"]).strip().upper()

        start = time.perf_counter()

        try:

            response = requests.post(
                API_URL,
                json={"prompt": prompt},
                timeout=30,
            )

            latency_ms = (
                time.perf_counter() - start
            ) * 1000

            response.raise_for_status()

            data = response.json()

            predicted = (
                "MALICIOUS"
                if data.get("is_malicious")
                else "SAFE"
            )

            results.append({
                "test_id": index + 1,
                "prompt": prompt,
                "expected": expected,
                "predicted": predicted,
                "correct": expected == predicted,
                "category": row.get("category"),
                "firewall_category": row.get(
                    "firewall_category"
                ),
                "source": row.get("source"),
                "risk_score": data.get(
                    "risk_score"
                ),
                "severity": data.get(
                    "severity"
                ),
                "action": data.get(
                    "action"
                ),
                "detection_source": data.get(
                    "detection_source"
                ),
                "ml_prediction": data.get(
                    "ml_prediction"
                ),
                "ml_confidence": data.get(
                    "ml_confidence"
                ),
                "obfuscation_detected": data.get(
                    "obfuscation_detected"
                ),
                "latency_ms": round(
                    latency_ms,
                    3
                ),
            })

        except Exception as error:

            results.append({
                "test_id": index + 1,
                "prompt": prompt,
                "expected": expected,
                "predicted": "ERROR",
                "correct": False,
                "category": row.get("category"),
                "firewall_category": row.get(
                    "firewall_category"
                ),
                "source": row.get("source"),
                "risk_score": None,
                "severity": None,
                "action": "ERROR",
                "detection_source": None,
                "ml_prediction": None,
                "ml_confidence": None,
                "obfuscation_detected": None,
                "latency_ms": None,
                "error": str(error),
            })

        completed = index + 1

        if completed % 50 == 0:
            print(
                f"Processed {completed}/{len(df)} samples..."
            )

    total_latency_ms = (
        time.perf_counter() - total_start
    ) * 1000

    results_df = pd.DataFrame(results)

    successful = results_df[
        results_df["predicted"] != "ERROR"
    ]

    if successful.empty:
        print("\nNo successful API responses.")
        return

    y_true = successful["expected"]
    y_pred = successful["predicted"]

    accuracy = accuracy_score(
        y_true,
        y_pred
    )

    precision = precision_score(
        y_true,
        y_pred,
        pos_label="MALICIOUS",
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred,
        pos_label="MALICIOUS",
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred,
        pos_label="MALICIOUS",
        zero_division=0,
    )

    cm = confusion_matrix(
        y_true,
        y_pred,
        labels=["SAFE", "MALICIOUS"],
    )

    false_positives = (
        (y_true == "SAFE")
        & (y_pred == "MALICIOUS")
    ).sum()

    false_negatives = (
        (y_true == "MALICIOUS")
        & (y_pred == "SAFE")
    ).sum()

    print("\n" + "=" * 75)
    print("API PERFORMANCE")
    print("=" * 75)

    print(
        f"Successful requests : {len(successful)}"
    )

    print(
        f"Failed requests     : "
        f"{len(results_df) - len(successful)}"
    )

    print(
        f"Accuracy            : {accuracy:.4f}"
    )

    print(
        f"Precision           : {precision:.4f}"
    )

    print(
        f"Recall              : {recall:.4f}"
    )

    print(
        f"F1 Score            : {f1:.4f}"
    )

    print(
        f"False Positives     : {false_positives}"
    )

    print(
        f"False Negatives     : {false_negatives}"
    )

    print("\nConfusion Matrix")
    print(
        "Rows = Actual, Columns = Predicted"
    )
    print(
        "              SAFE  MALICIOUS"
    )
    print(
        f"SAFE          {cm[0][0]:4d}"
        f"      {cm[0][1]:4d}"
    )
    print(
        f"MALICIOUS     {cm[1][0]:4d}"
        f"      {cm[1][1]:4d}"
    )

    print("\n" + "=" * 75)
    print("API LATENCY")
    print("=" * 75)

    print(
        f"Average latency : "
        f"{successful['latency_ms'].mean():.3f} ms"
    )

    print(
        f"Minimum latency : "
        f"{successful['latency_ms'].min():.3f} ms"
    )

    print(
        f"Maximum latency : "
        f"{successful['latency_ms'].max():.3f} ms"
    )

    print(
        f"Total runtime   : "
        f"{total_latency_ms / 1000:.2f} seconds"
    )

    print("\n" + "=" * 75)
    print("POLICY ACTION DISTRIBUTION")
    print("=" * 75)

    print(
        successful["action"]
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 75)
    print("DETECTION SOURCE DISTRIBUTION")
    print("=" * 75)

    print(
        successful["detection_source"]
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 75)
    print("OBFUSCATION DETECTION")
    print("=" * 75)

    print(
        successful["obfuscation_detected"]
        .value_counts()
        .to_string()
    )

    print("\n" + "=" * 75)
    print("RISK SCORE")
    print("=" * 75)

    print(
        f"Average risk : "
        f"{successful['risk_score'].mean():.2f}"
    )

    print(
        f"Maximum risk : "
        f"{successful['risk_score'].max():.2f}"
    )

    print("\n" + "=" * 75)
    print("SAVING RESULTS")
    print("=" * 75)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    results_df.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print(
        f"Results saved to:\n{OUTPUT_FILE}"
    )

    print("\n" + "=" * 75)
    print("FULL API EVALUATION COMPLETE")
    print("=" * 75)


if __name__ == "__main__":
    main()
    