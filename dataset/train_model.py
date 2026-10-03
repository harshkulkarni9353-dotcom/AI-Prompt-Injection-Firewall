import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# Load dataset
data = pd.read_csv("dataset/prompts.csv")

X = data["prompt"]
y = data["label"]


# Split dataset into training and testing data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# Create ML pipeline
model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2)
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000
        )
    )
])


# Train model
model.fit(X_train, y_train)


# Make predictions
y_pred = model.predict(X_test)


# Calculate evaluation metrics
accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(
    y_test,
    y_pred,
    pos_label="MALICIOUS"
)
recall = recall_score(
    y_test,
    y_pred,
    pos_label="MALICIOUS"
)
f1 = f1_score(
    y_test,
    y_pred,
    pos_label="MALICIOUS"
)


# Display results
print("\n===== MODEL EVALUATION =====")
print(f"Training samples : {len(X_train)}")
print(f"Testing samples  : {len(X_test)}")

print(f"\nAccuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1-Score  : {f1:.4f}")

print("\n===== CLASSIFICATION REPORT =====")
print(classification_report(y_test, y_pred))

print("\n===== CONFUSION MATRIX =====")
print(confusion_matrix(y_test, y_pred))


# Save trained model
joblib.dump(
    model,
    "dataset/prompt_injection_model.pkl"
)

print("\nModel saved successfully!")