# main.py
import os
import csv
import argparse
from config import FILES_DIR
from tools.semgrep_runner import run_semgrep
from tools.bandit_runner import run_bandit

TOOL_MAP = {
    "semgrep": ("semgrep_results_non_vuln.csv", run_semgrep),
    "bandit": ("bandit_results_non_vuln.csv", run_bandit)
}

def parse_args():
    parser = argparse.ArgumentParser(description="Run static analysis tools on Python files.")
    parser.add_argument(
        "--tools",
        nargs="+",
        choices=TOOL_MAP.keys(),
        default=list(TOOL_MAP.keys()),
        help="Specify which tools to run. Default: all"
    )
    return parser.parse_args()

def main():
    args = parse_args()

    writers = {}
    file_handlers = {}

    try:
        # Prepare CSV files for selected tools
        for tool in args.tools:
            csv_name, _ = TOOL_MAP[tool]
            f = open(csv_name, "w", newline="", encoding="utf-8")
            writer = csv.writer(f)
            writer.writerow(["filename", "line", "severity", "message", "cwe"])
            writers[tool] = writer
            file_handlers[tool] = f

        for filename in os.listdir(FILES_DIR):
            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(FILES_DIR, filename)
            print(f"\n🔍 Scanning: {filename}")

            for tool in args.tools:
                _, runner = TOOL_MAP[tool]
                runner(file_path, filename, writers[tool])

        print("\n✅ Results saved to:", ", ".join([TOOL_MAP[t][0] for t in args.tools]))
    finally:
        for f in file_handlers.values():
            f.close()

if __name__ == "__main__":
    main()
