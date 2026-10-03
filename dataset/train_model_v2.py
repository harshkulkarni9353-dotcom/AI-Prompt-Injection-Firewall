import time
import joblib
import pandas as pd

from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# ============================================================
# CONFIGURATION
# ============================================================

DATA_DIR = Path("dataset/processed")
MODEL_PATH = Path("dataset/prompt_injection_model_v2.pkl")

TRAIN_FILE = DATA_DIR / "train.csv"
VALIDATION_FILE = DATA_DIR / "validation.csv"

# ============================================================
# LOAD DATA
# ============================================================

print("Loading training data...")

train_df = pd.read_csv(TRAIN_FILE)
validation_df = pd.read_csv(VALIDATION_FILE)

print(f"Training samples   : {len(train_df)}")
print(f"Validation samples : {len(validation_df)}")

# Remove missing prompts
train_df = train_df.dropna(subset=["prompt", "label"])
validation_df = validation_df.dropna(subset=["prompt", "label"])

X_train = train_df["prompt"].astype(str)
y_train = train_df["label"]

X_val = validation_df["prompt"].astype(str)
y_val = validation_df["label"]

# ============================================================
# TF-IDF FEATURE EXTRACTION
# ============================================================

print("\nBuilding TF-IDF features...")

vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    min_df=2,
    max_df=0.98,
    sublinear_tf=True
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_val_tfidf = vectorizer.transform(X_val)

print(f"Training feature matrix   : {X_train_tfidf.shape}")
print(f"Validation feature matrix : {X_val_tfidf.shape}")

# ============================================================
# TRAIN MODEL
# ============================================================

print("\nTraining Logistic Regression model...")

start_time = time.perf_counter()

model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train_tfidf, y_train)

training_time = time.perf_counter() - start_time

print(f"Training completed in {training_time:.2f} seconds")

# ============================================================
# VALIDATION
# ============================================================

print("\nRunning validation...")

start_time = time.perf_counter()

y_pred = model.predict(X_val_tfidf)

prediction_time = time.perf_counter() - start_time

accuracy = accuracy_score(y_val, y_pred)
precision = precision_score(
    y_val,
    y_pred,
    pos_label="MALICIOUS",
    zero_division=0
)
recall = recall_score(
    y_val,
    y_pred,
    pos_label="MALICIOUS",
    zero_division=0
)
f1 = f1_score(
    y_val,
    y_pred,
    pos_label="MALICIOUS",
    zero_division=0
)

cm = confusion_matrix(
    y_val,
    y_pred,
    labels=["SAFE", "MALICIOUS"]
)

# ============================================================
# RESULTS
# ============================================================

print("\n======================================")
print("MODEL V2 VALIDATION RESULTS")
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
        y_val,
        y_pred,
        labels=["SAFE", "MALICIOUS"],
        zero_division=0
    )
)

print(f"Prediction time: {prediction_time:.4f} seconds")

if len(X_val) > 0:
    print(
        f"Average latency: "
        f"{(prediction_time / len(X_val)) * 1000:.4f} ms/prompt"
    )

# ============================================================
# SAVE MODEL + VECTORIZER
# ============================================================

print("\nSaving model...")

joblib.dump(
    {
        "model": model,
        "vectorizer": vectorizer
    },
    MODEL_PATH
)

print(f"Model saved to: {MODEL_PATH}")

print("\n======================================")
print("MODEL V2 TRAINING COMPLETE")
print("======================================")