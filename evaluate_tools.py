import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score

# ----------------- Config ------------------
GROUND_TRUTH_FILES = {
    "22": "files_CWE-22.csv",
    "79": "files_CWE-79.csv",
    "89": "files_CWE-89.csv"
}

TOOL_FILES = {
    "Bandit": "bandit_results.csv",
    "Semgrep": "semgrep_results.csv"
}

# ----------------- Load Ground Truth ------------------
cwe_files = {}
for cwe_id, filepath in GROUND_TRUTH_FILES.items():
    df = pd.read_csv(filepath)
    df = df[df["filename"].str.endswith(".py")]  # only .py files
    df["file_id"] = df["filename"].str.extract(r"(\d+)")
    df["normalized_filename"] = df["file_id"].astype(str)
    cwe_files[cwe_id] = df

# ----------------- Load Tool Outputs ------------------
tool_outputs = {}
for tool, filepath in TOOL_FILES.items():
    df = pd.read_csv(filepath)
    df["file_id"] = df["filename"].str.extract(r"(\d+)")
    df["cwe"] = df["cwe"].astype(str).str.extract(r"(\d+)")
    df["normalized_filename"] = df["file_id"].astype(str)
    tool_outputs[tool] = df

# ----------------- Metric Calculation ------------------
def compute_metrics(gt_df, tool_df, cwe_id):
    gt_set = set(gt_df["normalized_filename"])
    pred_set = set(tool_df[tool_df["cwe"].str.contains(cwe_id, na=False)]["normalized_filename"])

    all_files = gt_set | set(tool_df["normalized_filename"])
    df = pd.DataFrame({"normalized_filename": list(all_files)})
    df["true_label"] = df["normalized_filename"].isin(gt_set).astype(int)
    df["predicted"] = df["normalized_filename"].isin(pred_set).astype(int)

    return {
        "precision": precision_score(df["true_label"], df["predicted"], zero_division=0),
        "recall": recall_score(df["true_label"], df["predicted"], zero_division=0),
        "f1_score": f1_score(df["true_label"], df["predicted"], zero_division=0),
        "accuracy": accuracy_score(df["true_label"], df["predicted"])
    }

# ----------------- Run All Comparisons ------------------
results = []
for cwe_id in GROUND_TRUTH_FILES.keys():
    gt_df = cwe_files[cwe_id]
    for tool_name, tool_df in tool_outputs.items():
        metrics = compute_metrics(gt_df, tool_df, cwe_id)
        results.append({
            "Tool": tool_name,
            "CWE": cwe_id,
            **metrics
        })

# ----------------- Save Output ------------------
results_df = pd.DataFrame(results)
results_df.to_csv("per_cwe_tool_comparison_python_only.csv", index=False)
print("✅ Results saved to per_cwe_tool_comparison_python_only.csv")
