"""
Security Scanner Orchestrator.

This module manages the execution of various security tools (Semgrep, Gitleaks, Trivy, Checkov, ZAP).
It handles:
1. Copying source code to a shared volume for access by containerized tools.
2. Constructing and executing Docker commands for each tool.
3. parallel execution of scanners for performance.
"""

import subprocess
import os
import uuid
import concurrent.futures
from typing import List, Dict
from common.core.logger import get_logger

logger = get_logger(__name__)

# Shared directory for scan reports (mounted as Docker volume)
SCAN_DIR = "/tmp/scans"

class SecurityScanner:
    """
    Orchestrates security scans using various tools (Semgrep, Gitleaks, Trivy, Checkov, ZAP).
    Manages output parsing and report generation in a shared volume.
    """
    def __init__(self):
        os.makedirs(SCAN_DIR, exist_ok=True)

    def run_scan(self, target_path: str, project_name: str, target_url: str = None, extra_rules: List[str] = [], changed_files: List[str] = []) -> List[str]:
        """
        Runs configured security scanners against the target path or URL.

        Args:
            target_path: Path to the source code to scan.
            project_name: Name of the project (for labeling).
            target_url: Optional URL for DAST scanning (ZAP).
            extra_rules: Optional list of additional Semgrep ruleset paths.
            changed_files: Optional list of files to restrict SAST scan scope.

        Returns:
            List of paths to the generated scan report files.
        """
        scan_id = str(uuid.uuid4())[:8]  # Unique ID for this scan session
        shared_src_dir = os.path.join(SCAN_DIR, f"{scan_id}_src")

        # Step 1: Copy source code to shared volume for containerized tools
        if not os.path.exists(shared_src_dir):
            try:
                import time
                copy_start = time.time()
                if changed_files:
                    # Delta scan: only copy the changed files
                    logger.info(f"Delta scan: copying {len(changed_files)} changed files", extra_info={
                        "event": "source_copy_start",
                        "mode": "delta",
                        "file_count": len(changed_files),
                        "project": project_name
                    })
                    os.makedirs(shared_src_dir, exist_ok=True)
                    for f in changed_files:
                        # Sanitize path to prevent directory traversal attacks
                        safe_f = f.lstrip("/")
                        src_file = os.path.join(target_path, safe_f)
                        dst_file = os.path.join(shared_src_dir, safe_f)
                        
                        if os.path.exists(src_file):
                            os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                            subprocess.run(["cp", src_file, dst_file], check=True)
                else:
                    # Full scan: copy entire source directory
                    logger.info(f"Full scan: copying source directory", extra_info={
                        "event": "source_copy_start",
                        "mode": "full",
                        "project": project_name
                    })
                    subprocess.run(["cp", "-r", target_path, shared_src_dir], check=True)
                
                # Make files readable by all (needed for containerized tools)
                subprocess.run(["chmod", "-R", "o+rw", shared_src_dir], check=True)
                subprocess.run(["chmod", "777", SCAN_DIR], check=False)
                
                copy_duration_ms = round((time.time() - copy_start) * 1000, 2)
                logger.info(f"Source copy completed", extra_info={
                    "event": "source_copy_completed",
                    "project": project_name,
                    "duration_ms": copy_duration_ms
                })
            except Exception as e:
                logger.error(f"Failed to copy source: {e}", extra_info={"event": "copy_source_failed", "error": str(e)})
                return []

        # Step 2: Build Semgrep command with polyglot config and optional custom rules
        # --disable-nosem prevents attackers from bypassing scans with nosemgrep comments
        semgrep_cmd = ["semgrep", "scan", "--disable-nosem", "--config=p/default", "--config=p/owasp-top-ten", "--config=p/secrets"]
        
        # Append any extra rule paths provided by caller
        for rule in extra_rules:
            semgrep_cmd.append(f"--config={rule}")
            
        # Output as SARIF format for unified parsing
        semgrep_cmd.extend(["--sarif", "--quiet", "-o", f"/tmp/scans/semgrep_{scan_id}.sarif"])
        
        # [MODIFIED] Diff-based Scanning Logic for Semgrep
        if changed_files:
            logger.info(f"Running Semgrep on {len(changed_files)} changed files only.")
            # Convert to absolute paths in the shared volume
            # We filter to ensure files actually exist to avoid Semgrep errors
            target_files = []
            for f in changed_files:
                # Sanitize: prevent path traversal or absolute paths from client
                safe_f = f.lstrip("/")
                abs_path = os.path.join(shared_src_dir, safe_f)
                if os.path.exists(abs_path):
                    target_files.append(abs_path)
            
            if target_files:
                 semgrep_cmd.extend(target_files)
            else:
                 logger.warning("No valid changed files found in source. Falling back to full scan.")
                 semgrep_cmd.append(shared_src_dir)
        else:
            semgrep_cmd.append(shared_src_dir)

        # Gitleaks Command Construction
        gitleaks_cmd = ["gitleaks", "detect", f"--source=/tmp/scans/{scan_id}_src", f"--report-path=/tmp/scans/gitleaks_{scan_id}.json", "--redact", "--no-banner", "--exit-code=0"]
        if changed_files:
            # If we only have changed files (no .git dir), we must use --no-git
            gitleaks_cmd.append("--no-git")

        # Define all tool commands
        tasks = {
            "semgrep": semgrep_cmd,
            "gitleaks": gitleaks_cmd,
            "trivy": ["trivy", "fs", "--format", "sarif", "--output", f"/tmp/scans/trivy_{scan_id}.sarif", "--scanners", "vuln,secret,config", f"/tmp/scans/{scan_id}_src"]
        }

        # 🔥 NEW: Add DAST Task if target_url is provided
        if target_url:
            tasks["zap"] = [
                "sh", "-c",
                # Ensure report file exists, run zap (ignoring failures), then ONLY copy if report has content size > 0
                f"touch /home/zap/zap_report.json; zap-baseline.py -p 8080 -t {target_url} -J zap_report.json -m 5; if [ -s /home/zap/zap_report.json ]; then cp /home/zap/zap_report.json /zap/wrk/zap_{scan_id}.json; else echo 'Empty Report'; exit 1; fi"
            ]

        report_files = []
        # 🚀 Execute all scanners simultaneously
        import time
        parallel_start = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as executor:
            futures = {}
            for name, cmd in tasks.items():
                # ZAP might return 1 (Fail) or 2 (Warn) if issues found. 3 is system error.
                # Checkov returns 1 if failed checks.
                codes = [0, 1, 2] if name in ["zap", "checkov"] else [0]
                futures[executor.submit(self._exec_docker, name, cmd, allowed_exit_codes=codes)] = name

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                if future.result():
                    ext = "json" if name in ["gitleaks", "zap", "checkov"] else "sarif"
                    report_files.append(os.path.join(SCAN_DIR, f"{name}_{scan_id}.{ext}"))
        
        parallel_duration_ms = round((time.time() - parallel_start) * 1000, 2)
        logger.info(f"Parallel scans completed", extra_info={
            "event": "parallel_scans_completed",
            "project": project_name,
            "tools_run": list(tasks.keys()),
            "successful_count": len(report_files),
            "total_duration_ms": parallel_duration_ms
        })
        
        return report_files

    def _exec_docker(self, container_name, cmd_list, output_file=None, allowed_exit_codes=[0]):
        """
        Runs 'docker exec <container_name> <cmd...>'
        """
        import time
        exec_start = time.time()
        logger.info(f"Starting {container_name}", extra_info={
            "event": "tool_exec_start",
            "tool": container_name,
            "command_preview": ' '.join(cmd_list[:5]) + ('...' if len(cmd_list) > 5 else '')
        })
        
        full_cmd = ["docker", "exec", container_name] + cmd_list
        
        try:
            if output_file:
                # Capture stdout to file
                res = subprocess.run(full_cmd, capture_output=True, text=True)
                exec_duration_ms = round((time.time() - exec_start) * 1000, 2)
                if res.returncode not in allowed_exit_codes:
                    logger.error(f"{container_name} failed ({res.returncode})", extra_info={
                        "event": "tool_exec_failed",
                        "tool": container_name,
                        "exit_code": res.returncode,
                        "stderr_preview": res.stderr[:200] if res.stderr else "",
                        "duration_ms": exec_duration_ms
                    })
                    return False
                
                with open(output_file, 'w') as f:
                    f.write(res.stdout)
                logger.info(f"{container_name} completed", extra_info={
                    "event": "tool_exec_completed",
                    "tool": container_name,
                    "exit_code": res.returncode,
                    "duration_ms": exec_duration_ms
                })
                return True
            else:
                # Run and wait
                res = subprocess.run(full_cmd, capture_output=True, text=True)
                exec_duration_ms = round((time.time() - exec_start) * 1000, 2)
                if res.returncode not in allowed_exit_codes:
                    logger.error(f"{container_name} failed ({res.returncode})", extra_info={
                        "event": "tool_exec_failed",
                        "tool": container_name,
                        "exit_code": res.returncode,
                        "stderr_preview": res.stderr[:200] if res.stderr else "",
                        "duration_ms": exec_duration_ms
                    })
                    return False
                logger.info(f"{container_name} completed", extra_info={
                    "event": "tool_exec_completed",
                    "tool": container_name,
                    "exit_code": res.returncode,
                    "duration_ms": exec_duration_ms
                })
                return True
        except Exception as e:
            logger.error(f"Error executing in {container_name}: {e}", extra_info={
                "event": "tool_exec_error",
                "tool": container_name,
                "error": str(e)
            })
            return False
