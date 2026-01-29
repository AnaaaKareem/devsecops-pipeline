"""
Celery Task Definitions.

This module defines the Celery tasks that execute security scanning and AI triage
operations asynchronously. These tasks are dispatched by the Orchestrator API
endpoints and processed by Celery workers.

Tasks:
    execute_scan_job   - Runs a full security scan (SAST/DAST) on source code.
    execute_triage_job - Performs AI-powered triage on security findings.
"""

import asyncio
import time
from celery_conf import celery_app
from core import logic
from common.core.logger import get_logger

logger = get_logger(__name__)


@celery_app.task(name="execute_scan_job", bind=True)
def execute_scan_job(self, project: str, path: str, metadata: dict = None):
    """
    Celery task that executes a full security scan pipeline.
    
    This task clones the repository (if needed), runs SAST scanners (Semgrep,
    Gitleaks, Checkov, Trivy), optionally deploys a test environment for DAST
    scanning, and then triggers AI triage on the discovered findings.
    
    Args:
        self: Celery task instance (for retry capabilities).
        project (str): Full project name (e.g., "owner/repo").
        path (str): Absolute path to the source code directory.
        metadata (dict, optional): Additional scan metadata including:
            - ci_provider: CI/CD platform name.
            - branch: Git branch being scanned.
            - commit_sha: Git commit hash.
            - repo_url: Repository URL for cloning.
            - changed_files: List of files changed (for delta scans).
            
    Raises:
        Exception: Re-raises any exception after logging for Celery error handling.
    """
    start_time = time.time()
    task_id = self.request.id
    retry_count = self.request.retries
    
    logger.info(f"Celery task started: execute_scan_job", extra_info={
        "event": "celery_task_started",
        "task_id": task_id,
        "task_name": "execute_scan_job",
        "project": project,
        "retry_count": retry_count,
        "ci_provider": metadata.get("ci_provider") if metadata else None,
        "branch": metadata.get("branch") if metadata else None
    })
    
    try:
        asyncio.run(logic.perform_scan_background(project, path, metadata))
        duration_s = round(time.time() - start_time, 2)
        logger.info(f"Celery task completed: execute_scan_job", extra_info={
            "event": "celery_task_completed",
            "task_id": task_id,
            "task_name": "execute_scan_job",
            "project": project,
            "duration_s": duration_s
        })
    except Exception as e:
        duration_s = round(time.time() - start_time, 2)
        logger.error(f"Celery task failed: execute_scan_job - {e}", extra_info={
            "event": "celery_task_failed",
            "task_id": task_id,
            "task_name": "execute_scan_job",
            "project": project,
            "error_type": type(e).__name__,
            "error_msg": str(e),
            "duration_s": duration_s
        })
        raise e


@celery_app.task(name="execute_triage_job", bind=True)
def execute_triage_job(self, scan_id, project, sha, findings, token, local_source_path=None):
    """
    Celery task that performs AI-powered triage on security findings.
    
    This task invokes the LangGraph workflow which analyzes each finding using
    an LLM to determine true/false positives, generates remediation patches,
    and optionally creates pull requests for fixes.
    
    Args:
        self: Celery task instance (for retry capabilities).
        scan_id (int): Database ID of the associated Scan record.
        project (str): Full project name (e.g., "owner/repo").
        sha (str): Git commit hash being analyzed.
        findings (list): List of finding dictionaries from the scanner.
        token (str): GitHub access token for repository operations.
        local_source_path (str, optional): Path to local source code if already available.
            
    Raises:
        Exception: Re-raises any exception after logging for Celery error handling.
    """
    start_time = time.time()
    task_id = self.request.id
    retry_count = self.request.retries
    
    logger.info(f"Celery task started: execute_triage_job", extra_info={
        "event": "celery_task_started",
        "task_id": task_id,
        "task_name": "execute_triage_job",
        "project": project,
        "scan_id": scan_id,
        "findings_count": len(findings) if findings else 0,
        "retry_count": retry_count
    })
    
    try:
        asyncio.run(logic.run_brain_background(scan_id, project, sha, findings, token, local_source_path))
        duration_s = round(time.time() - start_time, 2)
        logger.info(f"Celery task completed: execute_triage_job", extra_info={
            "event": "celery_task_completed",
            "task_id": task_id,
            "task_name": "execute_triage_job",
            "project": project,
            "scan_id": scan_id,
            "duration_s": duration_s
        })
    except Exception as e:
        duration_s = round(time.time() - start_time, 2)
        logger.error(f"Celery task failed: execute_triage_job - {e}", extra_info={
            "event": "celery_task_failed",
            "task_id": task_id,
            "task_name": "execute_triage_job",
            "project": project,
            "scan_id": scan_id,
            "error_type": type(e).__name__,
            "error_msg": str(e),
            "duration_s": duration_s
        })
        raise e
