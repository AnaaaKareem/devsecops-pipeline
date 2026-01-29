"""
Parser Service.

This module is responsible for extracting findings from security scan reports.
It unifies the output from various tools (Semgrep, Trivy, Checkov, Gitleaks, ZAP) into a standard format.
It also reads source code snippets from the disk to provide context for the findings.
"""

# Import json for parsing report files and os for path handling
import json, os, glob
# Import types for hints
from typing import List, Dict, Any

# Paths/Files to ignore when parsing findings to reduce noise
FORBIDDEN_PATHS = [
    ".github",              # GitHub workflows
    "venv",                 # Python virtual environments
    "node_modules",         # Node.js dependencies
    "k8s-specifications",   # Kubernetes manifests (high noise)
    "docker-compose",       # Docker Compose files (configuration, not source)
    "Dockerfile",           # Dockerfiles (often intentional patterns)
    ".yml",                 # Generic YAML files
    ".yaml",                
    "semgrep.sarif",        # Our own scan outputs
    "gitleaks.json",
    "checkov.sarif"
]

# Shared directory where scan reports are stored
SCAN_DIR = "/tmp/scans"

# Define function to extract findings from raw file content based on filename/type
def extract_findings(content: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Parses a raw report file (bytes) and extracts standardized findings.

    Args:
        content (bytes): The raw file content uploaded to the server.
        filename (str): The name of the file (used to determine parsing logic, logic currently unified).

    Returns:
        List[Dict[str, Any]]: A list of dictionaries, each representing a finding with:
                              tool, rule_id, message, file, and line.
    """
    try:
        data = json.loads(content)
        extracted = []
        
        # --- SARIF Format (Semgrep, Trivy, Checkov) ---
        # SARIF is a standard format with runs[] containing results[]
        if "runs" in data:
            for run in data.get("runs", []):
                # Extract tool name from SARIF metadata
                tool = run.get("tool", {}).get("driver", {}).get("name", "Unknown")
                for res in run.get("results", []):
                    # Extract file path from deeply nested location structure
                    file_path = res.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    file_path = _clean_path(file_path)
                    
                    # Filter out findings in ignored paths to reduce noise
                    if any(forbidden in file_path for forbidden in FORBIDDEN_PATHS):
                        continue

                    extracted.append({
                        "tool": tool, 
                        "rule_id": res.get("ruleId"),
                        "message": res.get("message", {}).get("text", ""),
                        "file": _clean_path(file_path),
                        "line": res.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0)
                    })
        
        # --- Gitleaks Format (custom JSON array) ---
        # Gitleaks outputs an array of objects with specific field names
        elif isinstance(data, list) and len(data) > 0 and "Description" in data[0]:
            for issue in data:
                file_path = _clean_path(issue.get("File", ""))
                
                # Filter out findings in ignored paths
                if any(forbidden in file_path for forbidden in FORBIDDEN_PATHS):
                    continue

                extracted.append({
                    "tool": "Gitleaks", 
                    "rule_id": issue.get("RuleID"),
                    "message": issue.get("Description"), 
                    "file": _clean_path(file_path),
                    "line": issue.get("StartLine")
                })

        # --- OWASP ZAP Format (site[] with alerts[]) ---
        elif "site" in data:
            for site in data.get("site", []):
                for alert in site.get("alerts", []):
                    # Combine alert info into a detailed message
                    extracted.append({
                        "tool": "OWASP ZAP",
                        "rule_id": alert.get("pluginid"),
                        "message": f"{alert.get('name')} (Risk: {alert.get('riskdesc')})\nURL: {alert.get('url', 'N/A')}\nSolution: {alert.get('solution', 'N/A')}",
                        "file": "dast-report",   # DAST has no file, use placeholder
                        "line": 0,                # DAST has no line number
                        "dast_endpoint": alert.get("url")  # Store the vulnerable URL
                    })
        
        print(f"✅ Parser: Extracted {len(extracted)} valid findings from {filename}")
        return extracted

    except json.JSONDecodeError as e:
        # This will catch the "line 2 column 8" error
        print(f"⚠️ Skipping {filename}: Malformed JSON or empty report. Error: {e}")
        return []
    except Exception as e: 
        print(f"❌ Parser Error in {filename}: {e}")
        return []

def _clean_path(path: str) -> str:
    """
    Removes absolute prefixes from worker environment (e.g. /tmp/scans/xyz_src/)
    to ensure paths are relative to the repository root.
    """
    if not path: return ""
    
    # Common prefixes to strip
    import re
    # Matches /tmp/scans/<uuid>_src/ or /tmp/uploads/...
    # Also handle file:// scheme if present
    if path.startswith("file://"):
        path = path.replace("file://", "")
        
    cleaned = re.sub(r'^/tmp/(scans|uploads)/[^/]+/', '', path)
    
    # Also handle if it starts with slash but not in tmp (rare)
    if cleaned.startswith("/"):
        # Heuristic: try to keep only if it looks like a system path, otherwise strip leading slash
        cleaned = cleaned.lstrip("/")
        
    return cleaned

def populate_snippets(findings: List[Dict], source_root: str):
    """
    Reads the source code for each finding from the disk and adds it to the finding dict.

    Args:
        findings (List[Dict]): The list of findings to update.
        source_root (str): The root directory where the repo is checked out.
    """
    for f in findings:
        # Initialize snippet as None or a clear message to avoid KeyErrors later
        f["snippet"] = "⚠️ Source code not found on local Fedora disk."
        
        path = os.path.join(source_root, f["file"])
        
        if os.path.exists(path):
            try:
                with open(path, 'r', errors='replace') as s:
                    lines = s.readlines()
                    
                    if not lines:
                        f["snippet"] = "⚠️ File is empty."
                        continue

                    # SARIF/Gitleaks lines are 1-based; Python is 0-based
                    actual_line = f["line"] - 1 
                    
                    # Extract context (5 lines before and after)
                    start = max(0, actual_line - 5)
                    end = min(len(lines), actual_line + 5)
                    
                    extracted_snippet = "".join(lines[start:end])
                    if not extracted_snippet.strip():
                         f["snippet"] = "⚠️ Snippet is empty."
                    else:
                         f["snippet"] = extracted_snippet

            except Exception as e:
                print(f"❌ Could not read file {path}: {e}")

def parse_scan_report(scan_id: str) -> List[Dict[str, Any]]:
    """
    Parses all report files matching the scan_id in the SCAN_DIR.
    """
    all_findings = []
    
    if not os.path.exists(SCAN_DIR): return []

    # Look for any file containing scan_id
    files = glob.glob(os.path.join(SCAN_DIR, f"*{scan_id}*"))
    
    for fpath in files:
        if fpath.endswith("_src") or os.path.isdir(fpath): continue 
        
        try:
            with open(fpath, 'rb') as f:
                content = f.read()
                findings = extract_findings(content, os.path.basename(fpath))
                all_findings.extend(findings)
        except Exception as e:
            print(f"Failed to read {fpath}: {e}")
            
    return all_findings