import time
import joblib
import pandas as pd

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

DATA_DIR = Path("dataset/processed")
MODEL_PATH = Path("dataset/prompt_injection_model_v2.pkl")
TEST_FILE = DATA_DIR / "test.csv"

# ============================================================
# LOAD MODEL
# ============================================================

print("Loading Model V2...")

saved = joblib.load(MODEL_PATH)

model = saved["model"]
vectorizer = saved["vectorizer"]

# ============================================================
# LOAD UNSEEN TEST DATA
# ============================================================

print("Loading unseen test data...")

test_df = pd.read_csv(TEST_FILE)

test_df = test_df.dropna(subset=["prompt", "label"])

X_test = test_df["prompt"].astype(str)
y_test = test_df["label"]

print(f"Test samples: {len(test_df)}")

# ============================================================
# TRANSFORM TEST DATA
# ============================================================

X_test_tfidf = vectorizer.transform(X_test)

# ============================================================
# FINAL PREDICTION
# ============================================================

print("\nRunning final unseen evaluation...")

start_time = time.perf_counter()

y_pred = model.predict(X_test_tfidf)

prediction_time = time.perf_counter() - start_time

# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(y_test, y_pred)

precision = precision_score(
    y_test,
    y_pred,
    pos_label="MALICIOUS",
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    pos_label="MALICIOUS",
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    pos_label="MALICIOUS",
    zero_division=0
)

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=["SAFE", "MALICIOUS"]
)

# ============================================================
# RESULTS
# ============================================================

print("\n======================================")
print("FINAL UNSEEN TEST RESULTS")
print("======================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")

print("\nConfusion Matrix")
print("Labels: [SAFE, MALICIOUS]")
print(cm)

print("\nClassification Report")

print(
    classification_report(
        y_test,
        y_pred,
        labels=["SAFE", "MALICIOUS"],
        zero_division=0
    )
)

# ============================================================
# ERROR ANALYSIS
# ============================================================

results = test_df.copy()

results["predicted_label"] = y_pred

errors = results[
    results["label"] != results["predicted_label"]
]

false_positives = results[
    (results["label"] == "SAFE") &
    (results["predicted_label"] == "MALICIOUS")
]

false_negatives = results[
    (results["label"] == "MALICIOUS") &
    (results["predicted_label"] == "SAFE")
]

print("\n======================================")
print("ERROR ANALYSIS")
print("======================================")

print(f"Total errors      : {len(errors)}")
print(f"False positives   : {len(false_positives)}")
print(f"False negatives   : {len(false_negatives)}")

# ============================================================
# LATENCY
# ============================================================

average_latency_ms = (
    prediction_time / len(X_test)
) * 1000

print("\n======================================")
print("PERFORMANCE")
print("======================================")

print(f"Total prediction time : {prediction_time:.6f} seconds")
print(f"Average latency       : {average_latency_ms:.6f} ms/prompt")

# ============================================================
# CATEGORY ANALYSIS
# ============================================================

if "firewall_category" in results.columns:

    print("\n======================================")
    print("CATEGORY ERROR ANALYSIS")
    print("======================================")

    category_stats = (
        results
        .groupby("firewall_category")
        .apply(
            lambda group: pd.Series({
                "samples": len(group),
                "errors": (
                    group["label"] != group["predicted_label"]
                ).sum()
            }),
            include_groups=False
        )
        .reset_index()
    )

    category_stats["error_rate"] = (
        category_stats["errors"] /
        category_stats["samples"]
    )

    print(category_stats.to_string(index=False))

# ============================================================
# SAVE RESULTS
# ============================================================

OUTPUT_FILE = DATA_DIR / "test_results_v2.csv"

results.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\nResults saved to:")
print(OUTPUT_FILE)

print("\n======================================")
print("FINAL MODEL V2 EVALUATION COMPLETE")
print("======================================")