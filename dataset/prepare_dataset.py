from datasets import load_dataset
import pandas as pd
import os


# ==========================================
# 1. LOAD PUBLIC DATASET
# ==========================================

print("Loading public dataset...")

dataset = load_dataset("wambosec/prompt-injections")

public_train = dataset["train"].to_pandas()
public_test = dataset["test"].to_pandas()

print(f"Public train samples: {len(public_train)}")
print(f"Public test samples : {len(public_test)}")


# ==========================================
# 2. LOAD OUR EXISTING DATASET
# ==========================================

print("\nLoading existing project dataset...")

old_custom = pd.read_csv("dataset/prompts.csv")

print(f"Existing project samples: {len(old_custom)}")


# ==========================================
# 3. LOAD NEW CUSTOM SECURITY DATASET
# ==========================================

print("\nLoading new custom security dataset...")

new_custom = pd.read_csv("dataset/custom_security_data.csv")

print(f"New custom samples: {len(new_custom)}")


# ==========================================
# 4. MAP PUBLIC DATASET CATEGORIES
# ==========================================

def map_category(row):

    # Benign
    if row["label"] == 0:
        return "BENIGN"

    category = str(row["category"]).lower().strip()

    # Direct categories
    if "jailbreak" in category or "guardrail bypass" in category:
        return "JAILBREAK"

    if "authority" in category or "privilege escalation" in category:
        return "ROLE_MANIPULATION"

    if "social engineering" in category:
        return "SOCIAL_ENGINEERING"

    if "data exfiltration" in category:
        return "DATA_EXFILTRATION"

    if "tool abuse" in category or "downstream attack" in category:
        return "CYBER_ABUSE"

    # Obfuscation / evasion techniques
    obfuscation_terms = [
        "obfuscat",
        "unicode",
        "homoglyph",
        "encoding",
        "base64",
        "hex",
        "rot13",
        "rot47",
        "ascii",
        "steganograph",
        "zero-width",
        "zero width",
        "rtl",
        "right-to-left",
        "punycode",
        "leetspeak",
        "language mixing",
        "language-mixing",
        "romanized",
        "format string",
        "format-string",
        "escape",
        "backspace",
        "carriage-return",
        "control-character",
        "malformed",
        "broken syntax",
        "incomplete",
        "null-byte",
        "data-uri",
        "visual tricks",
    ]

    if any(term in category for term in obfuscation_terms):
        return "OBFUSCATION"

    # Prompt manipulation
    injection_terms = [
        "context manipulation",
        "context-manipulation",
        "linguistic tricks",
        "linguistic-tricks",
        "semantic camouflage",
        "semantic-camouflage",
        "output manipulation",
    ]

    if any(term in category for term in injection_terms):
        return "PROMPT_INJECTION"

    # Default malicious category
    return "PROMPT_INJECTION"


public_train["firewall_category"] = public_train.apply(
    map_category,
    axis=1
)

public_test["firewall_category"] = public_test.apply(
    map_category,
    axis=1
)


# ==========================================
# 5. STANDARDIZE OLD PROJECT DATA
# ==========================================

old_custom["firewall_category"] = old_custom["attack_type"]

old_custom.loc[
    old_custom["label"] == "SAFE",
    "firewall_category"
] = "BENIGN"

old_custom = old_custom[
    ["prompt", "label", "attack_type", "firewall_category"]
]

old_custom = old_custom.rename(
    columns={"attack_type": "category"}
)

old_custom["source"] = "OLD_PROJECT_DATA"


# ==========================================
# 6. STANDARDIZE NEW CUSTOM DATA
# ==========================================

new_custom = new_custom[
    ["prompt", "label", "firewall_category", "source"]
]

new_custom["category"] = new_custom["firewall_category"]

new_custom = new_custom[
    ["prompt", "label", "category", "firewall_category", "source"]
]


# ==========================================
# 7. STANDARDIZE PUBLIC DATA
# ==========================================

public_train["label"] = public_train["label"].map(
    {0: "SAFE", 1: "MALICIOUS"}
)

public_train["source"] = "PUBLIC_WAMBOSEC"

public_train = public_train[
    ["prompt", "label", "category", "firewall_category", "source"]
]


# ==========================================
# 8. COMBINE PUBLIC + CUSTOM DATA
# ==========================================

combined = pd.concat(
    [
        public_train,
        old_custom,
        new_custom
    ],
    ignore_index=True
)


# ==========================================
# 9. CLEAN PROMPTS
# ==========================================

combined["prompt"] = (
    combined["prompt"]
    .astype(str)
    .str.strip()
)

combined = combined[
    combined["prompt"].str.len() > 0
]


# ==========================================
# 10. REMOVE DUPLICATE PROMPTS
# ==========================================

before = len(combined)

combined = combined.drop_duplicates(
    subset=["prompt"]
)

after = len(combined)

print(f"\nRemoved duplicates: {before - after}")


# ==========================================
# 11. CREATE OUTPUT DIRECTORY
# ==========================================

os.makedirs(
    "dataset/processed",
    exist_ok=True
)


# ==========================================
# 12. SAVE COMBINED DATASET
# ==========================================

combined_file = (
    "dataset/processed/combined_dataset.csv"
)

combined.to_csv(
    combined_file,
    index=False
)


# ==========================================
# 13. SAVE PUBLIC TEST SEPARATELY
# ==========================================

public_test["label"] = public_test["label"].map(
    {0: "SAFE", 1: "MALICIOUS"}
)

public_test["source"] = "PUBLIC_WAMBOSEC_TEST"

public_test = public_test[
    ["prompt", "label", "category", "firewall_category", "source"]
]

public_test = public_test.drop_duplicates(
    subset=["prompt"]
)

test_file = (
    "dataset/processed/public_unseen_test.csv"
)

public_test.to_csv(
    test_file,
    index=False
)


# ==========================================
# 14. DISPLAY RESULTS
# ==========================================

print("\n======================================")
print("DATASET PREPARATION COMPLETE")
print("======================================")

print(f"\nCombined dataset: {len(combined)}")
print(f"Public test set : {len(public_test)}")

print("\nLabels:")
print(
    combined["label"].value_counts()
)

print("\nFirewall categories:")
print(
    combined["firewall_category"].value_counts()
)

print("\nData sources:")
print(
    combined["source"].value_counts()
)

print("\nFiles created:")
print(combined_file)
print(test_file)