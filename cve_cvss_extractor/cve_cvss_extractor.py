"""
Script to clone/pull the MITRE cvelistV5 repo, extract CVSS 4.0 and 3.1 vectors,
and write them to out.txt every hour.
"""

import os
import json
import subprocess
import time
from typing import List

# ---------------------------------------------------------------------------
# Repository configuration
# ---------------------------------------------------------------------------

GIT_REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
# The repository will live in a sibling folder next to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
GIT_DIR = os.path.join(SCRIPT_DIR, "cvelistV5")
CVES_DIR = os.path.join(GIT_DIR, "cves")
OUTPUT_FILE = "out.txt"

# ---------------------------------------------------------------------------
# Step 01 – Ensure repo is present and up to date
# ---------------------------------------------------------------------------

def step01() -> None:
    """Clone *cvelistV5* if missing, otherwise run **git pull** for updates."""

    if not os.path.isdir(GIT_DIR):
        print(f"[INFO] Repository not found – cloning into {GIT_DIR} …")
        try:
            subprocess.run(["git", "clone", GIT_REPO_URL, GIT_DIR], check=True)
            print("[OK] Clone completed.")
        except subprocess.CalledProcessError as err:
            print(f"[ERROR] git clone failed: {err}")
            return
    else:
        try:
            subprocess.run(["git", "pull"], cwd=GIT_DIR, check=True)
            print("[OK] git pull completed successfully.")
        except subprocess.CalledProcessError as err:
            print(f"[ERROR] git pull failed: {err}")

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

def find_cvss_v3_1_in_json(data) -> str:
    """Return the first string that starts with "CVSS:3.1" found anywhere in *data*."""
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, (dict, list)):
                found = find_cvss_v3_1_in_json(value)
                if found:
                    return found
            elif isinstance(value, str) and value.startswith("CVSS:3.1"):
                return value
    elif isinstance(data, list):
        for item in data:
            found = find_cvss_v3_1_in_json(item)
            if found:
                return found
    return ""

# ---------------------------------------------------------------------------
# File‑level processing
# ---------------------------------------------------------------------------

def process_file(file_path: str) -> List[str]:
    """Parse *file_path* and return a list with one formatted result line (or empty)."""
    try:
        with open(file_path, "r", encoding="utf-8") as fp:
            data = json.load(fp)

        if isinstance(data, list):
            print(f"[WARN] JSON is a list, skipping: {file_path}")
            return []

        cve_id = data.get("cveMetadata", {}).get("cveId", "")
        metrics = data.get("containers", {}).get("cna", {}).get("metrics", [])

        cvss_v4_0 = ""
        cvss_v3_1 = ""

        for metric in metrics:
            if "cvssV4_0" in metric:
                cvss_v4_0 = metric["cvssV4_0"].get("vectorString", "")
            if "cvssV3_1" in metric:
                cvss_v3_1 = metric["cvssV3_1"].get("vectorString", "")

        if not cvss_v3_1:
            cvss_v3_1 = find_cvss_v3_1_in_json(data)

        if cvss_v4_0:
            return [f"{cve_id}\t\t\t{cvss_v4_0}\t{cvss_v3_1}"]

    except Exception as err:
        print(f"[ERROR] Failed to process {file_path}: {err}")

    return []

# ---------------------------------------------------------------------------
# Step 02 – Walk directory and write results
# ---------------------------------------------------------------------------

def step02() -> None:
    """Traverse the *cves* directory, extract data, and write **out.txt**."""

    if not os.path.isdir(CVES_DIR):
        print(f"[WARN] CVEs directory not found: {CVES_DIR}")
        return

    results: List[str] = []

    for root, _dirs, files in os.walk(CVES_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)
            results.extend(process_file(file_path))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.writelines(line + "\n" for line in results)

    print(f"[OK] Scan complete – {len(results)} result(s) written to {OUTPUT_FILE}.")

# ---------------------------------------------------------------------------
# Main loop – run hourly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    while True:
        step01()
        step02()
        time.sleep(60 * 60)  # 1 hour