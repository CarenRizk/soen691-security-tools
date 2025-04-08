import pandas as pd
import os

# Load CSV files
csv_paths = [
    "files_CWE-22.csv",
    "files_CWE-79.csv",
    "files_CWE-89.csv"
]
dfs = [pd.read_csv(path) for path in csv_paths]

# Combine and filter only Python files
df_combined = pd.concat(dfs, ignore_index=True)
df_python = df_combined[df_combined["file_extension"] == "py"]

# Output directory
output_dir = "python_non_vuln_files"
os.makedirs(output_dir, exist_ok=True)

# Save each Python file
for _, row in df_python.iterrows():
    file_id = row["file_id"]
    filename = os.path.basename(row["filename"])
    code = row["file_before"]

    safe_name = f"{file_id}_{filename}"
    output_path = os.path.join(output_dir, safe_name)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(code)

print(f"Saved {len(df_python)} Python files to '{output_dir}'")
