"""
Core Logic for Security Scanning and Triage.

This module contains the primary business logic for the Orchestrator service,
extracted from main.py to support execution by Celery workers. It handles:

1. Repository cloning and source code preparation.
2. Invoking the Scanner service for SAST/DAST analysis.
3. Parsing scan results into normalized finding objects.
4. Triggering the LangGraph AI workflow for intelligent triage.
5. Persisting analysis results back to the database.

Key Functions:
    run_brain_background      - Executes AI triage on existing findings.
    perform_scan_background   - Runs the complete scan-to-triage pipeline.
"""

import os
import shutil
import uuid
import subprocess
import asyncio
import traceback
import httpx
from typing import List, Dict, Optional
from contextlib import contextmanager

from common.core import database, models
from common.core.logger import get_logger
from core.epss_worker import sync_epss_scores
from workflow import graph

logger = get_logger(__name__)

# --- Database Helper ---
@contextmanager
def get_db_session():
    """
    Context manager that provides a database session with automatic cleanup.
    
    Ensures that database connections are properly closed after use,
    even if an exception occurs during the session.
    
    Yields:
        Session: SQLAlchemy database session object.
    """
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def ensure_services_ready():
    """
    Polls dependent microservices until they report readiness.
    
    Checks the /readiness endpoints of Analysis and Remediation services,
    waiting up to 5 minutes for both to become available. This ensures
    that LLM models are loaded before processing begins.
    
    Returns:
        bool: True if all services are ready, False if timeout occurred.
    """
    services = [
        {"name": "Analysis", "url": os.getenv("ANALYSIS_SERVICE_URL", "http://analysis:8000") + "/readiness"},
        {"name": "Remediation", "url": os.getenv("REMEDIATION_SERVICE_URL", "http://remediation:8000") + "/readiness"}
    ]
    
    logger.info("⏳ Core Logic: Verifying AI Model Readiness...")
    
    timeout_minutes = 5
    end_time = asyncio.get_event_loop().time() + (60 * timeout_minutes)
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        while True:
            all_ready = True
            for svc in services:
                try:
                    resp = await client.get(svc["url"])
                    if resp.status_code != 200:
                        all_ready = False
                except:
                   all_ready = False
            
            if all_ready:
                logger.info("✅ All AI Services are Ready.", extra_info={"event": "dependencies_ready"})
                return True
            
            if asyncio.get_event_loop().time() > end_time:
                logger.error("AI Services Timed Out. Aborting scan.", extra_info={"event": "startup_timeout"})
                return False
                
            await asyncio.sleep(5)

async def run_brain_background(scan_id, project, sha, findings, token, local_source_path=None):
    """
    Executes AI-powered triage on a set of security findings.
    
    Orchestrates the LangGraph workflow which analyzes each finding using
    LLM-based intelligence to classify true/false positives, assess risk,
    generate remediation patches, and optionally create pull requests.
    
    Args:
        scan_id (int): Database ID of the Scan record.
        project (str): Full project name (e.g., "owner/repo").
        sha (str): Git commit hash being analyzed.
        findings (list): List of finding dictionaries to process.
        token (str): GitHub access token for repository operations.
        local_source_path (str, optional): Path to local source if available.
        
    Note:
        Updates scan status to 'completed' or 'failed' upon completion.
        Limits processing to 20 findings per run to manage resource usage.
    """
    # Step 0: Wait for AI services to be ready before proceeding
    if not await ensure_services_ready():
         logger.error("Scan aborted due to AI model unavailability.", extra_info={"event": "scan_aborted", "reason": "ai_models_unavailable", "scan_id": scan_id})
         # Mark scan as failed in database if services are unavailable
         with get_db_session() as db:
            db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "failed"})
            db.commit()
         return

    # Create unique temporary directory for this scan's workspace
    unique_id = str(uuid.uuid4())[:8]
    temp_src = f"/tmp/scans/brain_scan_{scan_id}_{unique_id}"
    
    # Limit findings to process to avoid overwhelming AI services
    TRIAGE_LIMIT = 20
    findings_to_process = findings[:TRIAGE_LIMIT]

    # Construct authenticated Git URL for cloning
    repo_url = f"https://x-access-token:{token}@github.com/{project}.git"

    logger.info(f"Starting analysis for {project}", extra_info={"event": "brain_scan_start", "project": project, "sha": sha})

    try:
        # Step 1: Prepare source code (clone from GitHub or use local path)
        if local_source_path and os.path.exists(local_source_path):
             # Use existing local source files (e.g., from upload)
             logger.info(f"Using local source path: {local_source_path}", extra_info={"project": project})
             if os.path.abspath(local_source_path) != os.path.abspath(temp_src):
                shutil.copytree(local_source_path, temp_src)
        elif project == "test/live-demo":
            # Special demo mode: create dummy vulnerable code for testing
            logger.info("🧪 Demo Mode: Skipping Git Clone. Creating dummy context.")
            os.makedirs(temp_src, exist_ok=True)
            with open(os.path.join(temp_src, "app.py"), "w") as f:
                f.write("import os\n\ndef process_request(user_input):\n    # Vulnerable to Command Injection\n    os.system('echo ' + user_input)\n")
        else:
            # Standard flow: clone repository from GitHub
            logger.info(f"twisted_rightwards_arrows Cloning {repo_url}...")
            await asyncio.to_thread(subprocess.run, ["git", "clone", "--depth", "1", repo_url, temp_src], check=True)
            # Checkout specific commit to match the scan context
            await asyncio.to_thread(subprocess.run, ["git", "-C", temp_src, "checkout", sha], check=True)

        # Step 2: Populate code snippets for each finding from source files
        from common.core.utils import populate_snippets
        await asyncio.to_thread(populate_snippets, findings_to_process, temp_src)

        # Step 3: Pre-persist findings to database before AI processing
        # This creates DB records so we can track and update them during workflow
        with get_db_session() as db:
            graph_findings = []
            for f in findings_to_process:
                db_finding = models.Finding(scan_id=scan_id, **f)
                db.add(db_finding)
                db.flush()  # Get the auto-generated ID
                f["id"] = db_finding.id  # Store ID back in finding dict
                graph_findings.append(f)
            db.commit()

        # Step 4: Sync EPSS exploitability scores for any CVE-related findings
        cve_ids = [f["rule_id"] for f in findings if f.get("rule_id", "").startswith("CVE-")]
        if cve_ids:
            logger.info(f"📡 Brain: Triggering exploitability sync for {len(cve_ids)} CVEs...")
            with get_db_session() as db:
                await asyncio.to_thread(sync_epss_scores, db, cve_ids)

        # Step 5: Execute the LangGraph workflow for AI-powered triage
        # This runs through: triage -> red_team -> prioritize -> remediate -> publish
        initial_state = {
            "findings": graph_findings,
            "current_index": 0,
            "analyzed_findings": [],
            "source_path": temp_src, 
            "project": project,
            "scan_id": scan_id 
        }

        final = await graph.graph_app.ainvoke(
            initial_state, 
            config={"recursion_limit": 150}  # High limit for complex workflows
        )

        # Step 6: Persist AI analysis results back to database
        with get_db_session() as db:
            for f in final.get("analyzed_findings", []):
                if f.get("id"):
                    # Only update columns that exist in the Finding model
                    valid_columns = {c.name for c in models.Finding.__table__.columns}
                    update_data = {k: v for k, v in f.items() if k in valid_columns}
                    db.query(models.Finding).filter(models.Finding.id == f["id"]).update(update_data)
            
            # Mark scan as completed after successful workflow execution
            db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "completed"})
            db.commit()
            logger.info(f"Database: Updated AI results for scan {scan_id}", extra_info={"event": "brain_scan_complete", "scan_id": scan_id, "status": "completed"})

    except Exception as e:
        logger.error(f"❌ Scan/Triage Failed: {e}")
        logger.error(traceback.format_exc())
        # Mark scan as failed on any error
        with get_db_session() as db:
            db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "failed"})
            db.commit()
    finally:
        # Always clean up temporary workspace directory
        if os.path.exists(temp_src):
            shutil.rmtree(temp_src)
            logger.info(f"Cleanup: Removed workspace {temp_src}", extra_info={"event": "cleanup", "path": temp_src})

async def perform_scan_background(project: str, path: str, metadata: Dict = None):
    """
    Executes a complete security scan pipeline from source code to triage.
    
    This is the main entry point for scan jobs. It performs:
    1. Creates a Scan record in the database.
    2. Clones the repository if a URL is provided.
    3. Auto-detects changed files for delta scanning.
    4. Detects application stack and deploys test environment for DAST.
    5. Invokes the Scanner service for SAST analysis.
    6. Parses scanner output into normalized findings.
    7. Triggers AI triage via run_brain_background().
    
    Args:
        project (str): Full project name (e.g., "owner/repo").
        path (str): Path to source code directory, or "/app" for remote scans.
        metadata (Dict, optional): Scan configuration including:
            - commit_sha: Git commit hash.
            - ci_provider: CI/CD platform name.
            - repo_url: Repository URL for cloning.
            - branch: Git branch being scanned.
            - target_url: URL for DAST scanning.
            - changed_files: List of changed files for delta scans.
            - reference_id: UUID for async status tracking.
            
    Note:
        Cleans up temporary directories and cloned repositories on completion.
        Updates scan status in database throughout the process.
    """
    try:
        logger.info(f"Starting analysis for {project}", extra_info={"event": "scan_start", "path": path, "project": project})
        
        # Extract metadata fields with sensible defaults
        if not metadata: metadata = {}
        repo_provider = "unknown"
        ci_provider = metadata.get("ci_provider", "manual-scan")
        branch = metadata.get("branch", "main")
        commit_sha = metadata.get("commit_sha", "latest")
        repo_url = metadata.get("repo_url", "")
        ci_job_url = metadata.get("run_url", "")
        target_url = metadata.get("target_url")  # URL for DAST scanning
        
        # Validate source path exists before proceeding
        if not os.path.exists(path):
            logger.error(f"❌ Error: Target path does not exist: {path}")
            return

        logger.info(f"DEBUG: repo_url='{repo_url}', path='{path}'")

        # Step 0: Create Scan record in database for tracking
        scan_id = None
        with get_db_session() as db:
            try:
                scan = models.Scan(
                    project_name=project, 
                    commit_sha=commit_sha,
                    source_platform=repo_provider,
                    repo_provider=repo_provider,
                    ci_provider=ci_provider,
                    branch=branch,
                    repo_url=repo_url,
                    source_url="localhost",
                    ci_job_url=ci_job_url,
                    reference_id=metadata.get("reference_id"),  # UUID for async tracking
                    status="scanning"  # Initial status
                )
                db.add(scan)
                db.commit()
                db.refresh(scan)  # Get auto-generated ID
                scan_id = scan.id
                logger.info(f"✅ Created Scan ID {scan_id} for {project}", extra_info={"event": "scan_created", "scan_id": scan_id})
            except Exception as e:
                logger.error(f"DB Error: {e}")
                return

        # Step 0.5: Clone remote repository if needed
        # Only clone if repo_url is provided and local path doesn't have source
        temp_clone_path = None
        if repo_url and (path == "/app" or not os.path.exists(path)):
             scan_uid = str(uuid.uuid4())[:8]
             temp_clone_path = f"/tmp/scans/{scan_uid}_src"
             
             # Inject GitHub token for authentication if available
             clone_url = repo_url
             github_token = os.getenv("GITHUB_TOKEN")
             if github_token and "github.com" in repo_url and "@" not in repo_url:
                 clone_url = repo_url.replace("https://", f"https://oauth2:{github_token}@")

             logger.info(f"🌍 Remote Scan Detected. Cloning {repo_url}...", extra_info={"event": "git_clone_start"})
             try:
                 # Clone with depth=2 to allow diff detection between commits
                 subprocess.run(["git", "clone", "--depth", "2", clone_url, temp_clone_path], check=True)
                 # Checkout specific commit if not "latest"
                 if commit_sha and commit_sha != "latest":
                      subprocess.run(["git", "-C", temp_clone_path, "checkout", commit_sha], check=True)
                 path = temp_clone_path  # Use cloned path for scanning
             except Exception as e:
                 logger.error(f"Git Clone Failed: {e}")
                 with get_db_session() as db:
                    db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "failed"})
                    db.commit()
                 return

        # Step 0.7: Auto-detect changed files for delta scanning
        # This optimizes scans by only analyzing modified code
        if not metadata.get("changed_files") and os.path.exists(os.path.join(path, ".git")):
            try:
                logger.info("🕵️ Auto-detecting changed files...")
                diff_cmd = ["git", "-C", path, "diff", "--name-only", "HEAD^", "HEAD"]
                res = subprocess.run(diff_cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    detected = [l.strip() for l in res.stdout.splitlines() if l.strip()]
                    if detected:
                        logger.info(f"✅ Detected {len(detected)} changed files.")
                        metadata["changed_files"] = detected
            except Exception as e:
                 logger.error(f"Failed to detect changed files: {e}")
        
        changed_files = metadata.get("changed_files", [])

        # Step 0.8: Auto-detect application stack and deploy test environment for DAST
        if not target_url:
            try:
                from core.detector import detect_application_stack
                app_info = detect_application_stack(path)
                
                # If web application detected, deploy ephemeral test environment
                if app_info["detected"] and app_info["type"] == "web":
                    logger.info(f"Detected Web Application: {app_info['framework']}")
                    SANDBOX_URL = os.getenv("SANDBOX_SERVICE_URL", "http://sandbox:8000")
                    async with httpx.AsyncClient() as client:
                        # Request Sandbox service to deploy the app
                        resp = await client.post(f"{SANDBOX_URL}/deploy", json={
                            "source_path": path,
                            "port": app_info["port"],
                            "start_cmd": app_info.get("start_command")
                        }, timeout=300)
                        if resp.status_code == 200:
                            data = resp.json()
                            if data.get("success"):
                                target_url = data["url"]  # Use deployed URL for DAST
                                logger.info(f"🚀 Ephemeral Target Deployed: {target_url}")
            except Exception as e:
                logger.error(f"Auto-Detection Failed: {e}")

        # Step 1: Execute security scanners via Scanner service
        SCANNER_URL = os.getenv("SCANNER_SERVICE_URL", "http://scanner:8000")
        try:
            async with httpx.AsyncClient() as client:
                # Send scan request with target path and optional DAST URL
                resp = await client.post(f"{SCANNER_URL}/scan", json={
                    "target_path": path,
                    "project_name": project,
                    "target_url": target_url,
                    "changed_files": changed_files  # For delta scanning
                }, timeout=600)  # 10 minute timeout for large scans
                resp.raise_for_status()
                data = resp.json()
                report_paths = data.get("reports", [])  # Paths to generated reports
        except Exception as e:
            logger.error(f"Scan failed calling service: {e}")
            with get_db_session() as db:
                db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "failed"})
                db.commit()
            return

        # Step 2: Parse scanner output files into normalized findings
        all_findings = []
        for report in report_paths:
             try:
                with open(report, "rb") as f: content = f.read()
                async with httpx.AsyncClient() as client:
                    # Send report file to Scanner service for parsing
                    files = {'file': (os.path.basename(report), content)}
                    resp = await client.post(f"{SCANNER_URL}/parse", files=files)
                    if resp.status_code == 200:
                        all_findings.extend(resp.json().get("findings", []))
             except Exception as e:
                logger.error(f"Failed to parse {report}: {e}")

        # Step 3: Update scan status to 'analyzing' before AI triage
        with get_db_session() as db:
             db.query(models.Scan).filter(models.Scan.id == scan_id).update({"status": "analyzing"})
             db.commit()

        logger.info(f"🧩 Parsed {len(all_findings)} finding(s). Sending to Brain...")
        
        # Step 4: Trigger AI triage workflow with parsed findings
        await run_brain_background(scan_id, project, commit_sha, all_findings, "no-token", local_source_path=path)

    except Exception as e:
        logger.error(f"FATAL CRASH in perform_scan: {str(e)}")
        logger.error(traceback.format_exc())
    finally:
        # Clean up temporary upload directories
        if path and "/tmp/scans/uploads/" in path and os.path.exists(path):
            shutil.rmtree(path)
            logger.info(f"🗑️ Upload Cleanup: Removed {path}")
        
        # Clean up any cloned repository directories
        if 'temp_clone_path' in locals() and temp_clone_path and os.path.exists(temp_clone_path):
             shutil.rmtree(temp_clone_path)
             logger.info(f"🗑️ Clone Cleanup: Removed {temp_clone_path}")
