# CVSS Extractor

> **Python script that clones or updates the MITRE `cvelistV5` repository and extracts CVSS 4.0 and 3.1 vector strings into `out.txt`.**

On the first run the script performs a **`git clone`**; on subsequent runs it executes **`git pull`** to stay in sync. After every update, it parses the JSON files under `cves/` and writes a tab‑separated line containing the CVE ID, CVSS 4.0 vector, and (if available) CVSS 3.1 vector.

## Workflow

| Step  | Action |
|-------|--------|
| **step01** | If the repository is missing, run `git clone`; otherwise run `git pull` to fetch the latest JSON files. |
| **step02** | Recursively scan the `cves` directory, extract the required fields, and append the results to `out.txt`. |

The two steps repeat **once every hour**.

## Requirements

- Python ≥ 3.8
- `git` command‑line client (available on the system `PATH`)

## Installation & Usage

**Run the script**

   Place `cve_cvss_extractor.py` in a directory of your choice and execute:

   ```bash
   python cve_cvss_extractor.py
