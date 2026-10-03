import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parent.parent)

)
import time
import joblib
import pandas as pd

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

from app.firewall.detector import detect_prompt_injection
from app.firewall.hybrid_detector import hybrid_detect


# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = Path("dataset/processed")
MODEL_PATH = Path("dataset/prompt_injection_model_v2.pkl")
TEST_FILE = DATA_DIR / "test.csv"
OUTPUT_FILE = DATA_DIR / "rule_ml_hybrid_results.csv"


# ============================================================
# LOAD MODEL
# ============================================================

print("Loading Model V2...")

saved = joblib.load(MODEL_PATH)

model = saved["model"]
vectorizer = saved["vectorizer"]


# ============================================================
# LOAD TEST DATA
# ============================================================

print("Loading final test dataset...")

test_df = pd.read_csv(TEST_FILE)

test_df = test_df.dropna(
    subset=["prompt", "label"]
).reset_index(drop=True)

prompts = test_df["prompt"].astype(str)
actual = test_df["label"]

print(f"Test samples: {len(test_df)}")


# ============================================================
# ML DETECTION
# ============================================================

print("\nRunning ML detector...")

X_test = vectorizer.transform(prompts)

start = time.perf_counter()

ml_predictions = model.predict(X_test)

ml_time = time.perf_counter() - start


# ============================================================
# RULE DETECTION
# ============================================================

print("Running rule detector...")

rule_predictions = []

start = time.perf_counter()

for prompt in prompts:

    result = detect_prompt_injection(prompt)

    if result["is_malicious"]:
        rule_predictions.append("MALICIOUS")
    else:
        rule_predictions.append("SAFE")

rule_time = time.perf_counter() - start


# ============================================================
# HYBRID DETECTION
# ============================================================

print("Running hybrid detector...")

hybrid_predictions = []

start = time.perf_counter()

for prompt in prompts:

    result = hybrid_detect(prompt)

    if result["is_malicious"]:
        hybrid_predictions.append("MALICIOUS")
    else:
        hybrid_predictions.append("SAFE")

hybrid_time = time.perf_counter() - start


# ============================================================
# METRIC FUNCTION
# ============================================================

def calculate_metrics(name, predictions, elapsed_time):

    accuracy = accuracy_score(
        actual,
        predictions
    )

    precision = precision_score(
        actual,
        predictions,
        pos_label="MALICIOUS",
        zero_division=0
    )

    recall = recall_score(
        actual,
        predictions,
        pos_label="MALICIOUS",
        zero_division=0
    )

    f1 = f1_score(
        actual,
        predictions,
        pos_label="MALICIOUS",
        zero_division=0
    )

    cm = confusion_matrix(
        actual,
        predictions,
        labels=["SAFE", "MALICIOUS"]
    )

    false_positives = cm[0][1]
    false_negatives = cm[1][0]

    average_latency = (
        elapsed_time / len(prompts)
    ) * 1000

    print("\n--------------------------------------")
    print(name)
    print("--------------------------------------")

    print(f"Accuracy        : {accuracy:.4f}")
    print(f"Precision       : {precision:.4f}")
    print(f"Recall          : {recall:.4f}")
    print(f"F1 Score        : {f1:.4f}")

    print(f"False Positives : {false_positives}")
    print(f"False Negatives : {false_negatives}")

    print(f"Total Time      : {elapsed_time:.6f} seconds")
    print(f"Latency         : {average_latency:.6f} ms/prompt")

    print("\nConfusion Matrix")
    print("Labels: [SAFE, MALICIOUS]")
    print(cm)

    return {
        "detector": name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "total_time_seconds": elapsed_time,
        "average_latency_ms": average_latency
    }


# ============================================================
# CALCULATE RESULTS
# ============================================================

print("\n======================================")
print("RULE vs ML vs HYBRID")
print("======================================")

rule_result = calculate_metrics(
    "RULE",
    rule_predictions,
    rule_time
)

ml_result = calculate_metrics(
    "ML",
    ml_predictions,
    ml_time
)

hybrid_result = calculate_metrics(
    "HYBRID",
    hybrid_predictions,
    hybrid_time
)


# ============================================================
# SAVE RESULTS
# ============================================================

comparison = pd.DataFrame([
    rule_result,
    ml_result,
    hybrid_result
])

comparison.to_csv(
    OUTPUT_FILE,
    index=False
)


print("\n======================================")
print("COMPARISON COMPLETE")
print("======================================")

print(comparison.to_string(index=False))

print("\nResults saved to:")
print(OUTPUT_FILE)  