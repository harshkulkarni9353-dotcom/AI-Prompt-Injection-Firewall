import pandas as pd
from sklearn.model_selection import train_test_split
from pathlib import Path

INPUT_FILE = "dataset/processed/combined_dataset.csv"
OUTPUT_DIR = Path("dataset/processed")

df = pd.read_csv(INPUT_FILE)

print("Original dataset:", len(df))

# First split: 85% development, 15% final test
development, test = train_test_split(
    df,
    test_size=0.15,
    random_state=42,
    stratify=df["label"]
)

# Second split: 70% train, 15% validation
train, validation = train_test_split(
    development,
    test_size=0.1765,
    random_state=42,
    stratify=development["label"]
)

# Save datasets
train.to_csv(OUTPUT_DIR / "train.csv", index=False)
validation.to_csv(OUTPUT_DIR / "validation.csv", index=False)
test.to_csv(OUTPUT_DIR / "test.csv", index=False)

print("\n======================================")
print("DATASET SPLIT COMPLETE")
print("======================================")

print(f"\nTrain samples      : {len(train)}")
print(f"Validation samples : {len(validation)}")
print(f"Test samples       : {len(test)}")

print("\nTrain labels:")
print(train["label"].value_counts())

print("\nValidation labels:")
print(validation["label"].value_counts())

print("\nTest labels:")
print(test["label"].value_counts())

print("\nFiles created:")
print("dataset/processed/train.csv")
print("dataset/processed/validation.csv")
print("dataset/processed/test.csv")