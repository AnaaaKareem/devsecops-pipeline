"""
Security Dashboard Service.

This service serves the frontend and provides APIs for data visualization.
It connects to PostgreSQL for historical data and Redis for real-time status updates/caching.
Key features:
- Global and Per-Project Statistics
- Real-time Scan Progress Tracking
- Vulnerability Trends and Metrics
"""

from fastapi import FastAPI, Depends, Request
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
import redis
import json
import os
import sys

# Try to load .env, but don't fail if missing (Docker uses env vars)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".env"))
except ImportError:
    pass

print("Starting Dashboard Service...")

from core import models, database
from core.logger import get_logger

logger = get_logger(__name__)

app = FastAPI(title="Security Dashboard")

# Setup Templates
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# Mount static files directory for CSS/JS
STATIC_DIR = os.path.join(BASE_DIR, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# --- REDIS SETUP ---
# Redis is used for caching stats and real-time scan progress
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
try:
    cache = redis.from_url(REDIS_URL, decode_responses=True)
    cache.ping()  # Verify connection
    logger.info("Connected to Redis", extra_info={"event": "redis_connected", "url": REDIS_URL})
except redis.ConnectionError:
    logger.warning("Redis not available, caching disabled", extra_info={"event": "redis_failed"})
    cache = None  # Graceful degradation - app works without cache

@app.get("/")
def dashboard(request: Request, db: Session = Depends(database.get_db)):
    """
    Renders the main dashboard HTML.
    """
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health", status_code=200)
def health_check():
    return {"status": "healthy", "service": "dashboard"}

@app.get("/api/repos")
def get_repos(db: Session = Depends(database.get_db)):
    """
    Returns a list of all unique repository names.
    """
    repos = db.query(models.Scan.project_name).distinct().all()
    # repos is a list of tuples like [('user/repo1',), ('user/repo2',)]
    return [r[0] for r in repos if r[0]]

@app.get("/api/stats")
async def get_stats(repo: str = None, db: Session = Depends(database.get_db)):
    """
    Returns aggregated security statistics, optionally filtered by repository.
    Cached in Redis for 60 seconds.
    """
    # Build cache key based on repo filter (global or per-repo stats)
    cache_key = f"dashboard_stats_{repo}" if repo else "dashboard_stats_global"

    try:
        # Step 1: Check Redis cache (60 second TTL)
        if cache:
            cached_data = cache.get(cache_key)
            if cached_data:
                logger.info(f"Cache hit: {cache_key}", extra_info={
                    "event": "cache_hit",
                    "key": cache_key,
                    "repo_filter": repo
                })
                return json.loads(cached_data)

        # Step 2: Cache miss - query database
        import time
        query_start = time.time()
        logger.info(f"Cache miss: {cache_key}", extra_info={
            "event": "cache_miss",
            "key": cache_key,
            "repo_filter": repo
        })
        
        # Base Queries
        scan_query = db.query(models.Scan)
        finding_query = db.query(models.Finding).join(models.Scan)

        # Filter by Completed Status
        scan_query = scan_query.filter(models.Scan.status == "completed")
        finding_query = finding_query.filter(models.Scan.status == "completed")

        if repo:
            scan_query = scan_query.filter(models.Scan.project_name == repo)
            finding_query = finding_query.filter(models.Scan.project_name == repo)

        total_scans = scan_query.count()
        total_findings = finding_query.count()
        
        # Severity Counts
        critical = finding_query.filter(models.Finding.severity == "Critical").count()
        high = finding_query.filter(models.Finding.severity == "High").count()
        medium = finding_query.filter(models.Finding.severity == "Medium").count()
        low = finding_query.filter(models.Finding.severity == "Low").count()
        
        # AI Performance
        false_positives = finding_query.filter(models.Finding.ai_verdict == "FP").count()
        fixed_issues = finding_query.filter(models.Finding.remediation_patch != None).count()

        # Real System Health Check
        redis_status = "connected" if cache else "disconnected"
        db_status = "connected"
        try:
            db.execute(func.text("SELECT 1"))
        except Exception:
            db_status = "error"

        # --- MTTF (Mean Time To Fix) Calculation ---
        # Split by AI-assisted vs manual remediation
        
        # AI-Assisted: findings with remediation_patch generated
        mttf_ai_query = finding_query.with_entities(
            func.avg(func.extract('epoch', models.Finding.resolved_at) - func.extract('epoch', models.Finding.created_at))
        ).filter(models.Finding.resolved_at != None, models.Finding.remediation_patch != None)
        
        # Manual: findings without AI-generated patch
        mttf_manual_query = finding_query.with_entities(
            func.avg(func.extract('epoch', models.Finding.resolved_at) - func.extract('epoch', models.Finding.created_at))
        ).filter(models.Finding.resolved_at != None, models.Finding.remediation_patch == None)

        mttf_ai_seconds = mttf_ai_query.scalar() or 0
        mttf_manual_seconds = mttf_manual_query.scalar() or 0
        
        # Convert seconds to hours for display
        mttf_ai_hours = round(float(mttf_ai_seconds) / 3600, 2)
        mttf_manual_hours = round(float(mttf_manual_seconds) / 3600, 2)
        
        # Overall average (for legacy support)
        mttf_avg_hours = round((mttf_ai_hours + mttf_manual_hours) / 2, 2) if (mttf_ai_hours and mttf_manual_hours) else (mttf_ai_hours or mttf_manual_hours)

        # --- CI/CD Provider Distribution ---
        ci_stats = scan_query.with_entities(
            models.Scan.ci_provider, func.count(models.Scan.id)
        ).group_by(models.Scan.ci_provider).all()
        ci_distribution = {provider or "unknown": count for provider, count in ci_stats}

        # --- Tool Distribution ---
        tool_stats = finding_query.with_entities(
            models.Finding.tool, func.count(models.Finding.id)
        ).group_by(models.Finding.tool).all()
        tool_distribution = {tool or "unknown": count for tool, count in tool_stats}

        # --- AI Efficacy Metrics ---
        tp_count = finding_query.filter(models.Finding.ai_verdict == "TP").count()
        total_ai_decisions = tp_count + false_positives
        # Efficacy = percentage of true positives among all AI decisions
        ai_efficacy_score = round((tp_count / total_ai_decisions * 100), 1) if total_ai_decisions > 0 else 0.0
        
        # Average confidence score for true positive findings
        avg_conf = db.query(func.avg(models.Finding.ai_confidence)).filter(models.Finding.ai_verdict == 'TP').scalar() or 0.0

        # --- Risk Ranking (Top 5 Riskiest Projects) ---
        risk_per_repo = []
        try:
            risk_query = db.query(
                models.Scan.project_name, func.sum(models.Finding.risk_score)
            ).join(models.Finding).group_by(models.Scan.project_name).order_by(func.sum(models.Finding.risk_score).desc()).limit(5).all()
            risk_per_repo = [{"repo": r[0], "risk": float(r[1] or 0.0)} for r in risk_query]
        except Exception:
            risk_per_repo = []

        # --- Trend Data for Visualization ---
        # Global view: X-axis = Projects, Y-axis = Severity counts (stacked chart)
        # Repo view: X-axis = Severity levels, Y-axis = Count (bar chart)
        trend_data = {
            "mode": "global" if not repo else "repo",
            "labels": [],
            "critical": [],
            "high": [],
            "medium": []
        }

        if not repo:
            # GLOBAL VIEW: Aggregate latest scan for EACH project
            # Get all unique projects
            projects = db.query(models.Scan.project_name).distinct().all()
            projects = [p[0] for p in projects if p[0]]
            
            for p_name in projects:
                # Get latest COMPLETED scan
                latest_scan = db.query(models.Scan).filter(
                    models.Scan.project_name == p_name,
                    models.Scan.status == "completed"
                ).order_by(models.Scan.timestamp.desc()).first()
                
                if latest_scan:
                    trend_data["labels"].append(p_name)
                    
                    # Count severities
                    c = db.query(models.Finding).filter(models.Finding.scan_id == latest_scan.id, models.Finding.severity == "Critical").count()
                    h = db.query(models.Finding).filter(models.Finding.scan_id == latest_scan.id, models.Finding.severity == "High").count()
                    m = db.query(models.Finding).filter(models.Finding.scan_id == latest_scan.id, models.Finding.severity == "Medium").count()
                    
                    trend_data["critical"].append(c)
                    trend_data["high"].append(h)
                    trend_data["medium"].append(m)
        else:
            # REPO VIEW: Show simple severity distribution for this repo's latest scan
            trend_data["mode"] = "repo"
            trend_data["labels"] = ["Critical", "High", "Medium"]
            
            # Use the already calculated critical/high/medium from line 109-111 
            # (which are filtered by 'repo' already if it exists)
            # BUT wait, lines 109-111 are aggregates across ALL scans if finding_query wasn't limited to latest.
            # Let's check lines 98-99: finding_query = finding_query.filter(models.Scan.status == "completed")
            # And lines 101-103: if repo: finding_query filter by repo.
            # So 'critical', 'high', etc currently are TOTAL findings across HISTORY for that repo.
            
            # The prompt asks for specific visualization.
            # "Per repository have the X-axis Showcase the Critical, High, Medium and the Y-Axis showcases the count for each one of them"
            # It usually implies *Current* state, i.e., Latest Scan.
            
            latest_scan = db.query(models.Scan).filter(
                models.Scan.project_name == repo,
                models.Scan.status == "completed"
            ).order_by(models.Scan.timestamp.desc()).first()
            
            if latest_scan:
                c = db.query(models.Finding).filter(models.Finding.scan_id == latest_scan.id, models.Finding.severity == "Critical").count()
                h = db.query(models.Finding).filter(models.Finding.scan_id == latest_scan.id, models.Finding.severity == "High").count()
                m = db.query(models.Finding).filter(models.Finding.scan_id == latest_scan.id, models.Finding.severity == "Medium").count()
                
                # Single dataset logic will be handled by frontend using these values
                # We can pack them into 'critical' list for simplicity or a generic 'counts' list
                trend_data["critical"] = [c, h, m] # Re-using this field to carry the data array [C, H, M]
                trend_data["high"] = []
                trend_data["medium"] = []

        # Count unique repos for dashboard stat
        total_repos = len(db.query(models.Scan.project_name).distinct().all())

        data = {
            "system_health": {
                "database": db_status,
                "redis": redis_status,
                "status": "operational" if (db_status == "connected" and redis_status == "connected") else "degraded"
            },
            "total_scans": total_scans,
            "total_findings": total_findings,
            "total_repos": total_repos,
            "severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            },
            "ai_metrics": {
                "false_positives": false_positives,
                "auto_fixed": fixed_issues,
                "efficacy_percent": ai_efficacy_score,
                "confidence_avg": round(float(avg_conf) * 100, 1)
            },
            "devsecops_metrics": {
                "mttf_hours": mttf_avg_hours,
                "mttf_ai_hours": mttf_ai_hours,
                "mttf_manual_hours": mttf_manual_hours,
                "ci_distribution": ci_distribution,
                "tool_distribution": tool_distribution,
                "risk_per_repo": risk_per_repo,
                "trend_data": trend_data
            }
        }

        # 3. Set Cache
        if cache:
            query_duration_ms = round((time.time() - query_start) * 1000, 2)
            cache.setex(cache_key, 60, json.dumps(data))
            logger.info(f"Cache set: {cache_key}", extra_info={
                "event": "cache_set",
                "key": cache_key,
                "ttl": 60,
                "query_duration_ms": query_duration_ms
            })

        return data
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Return a partial error response or re-raise
        logger.error(f"Error in /stats: {e}", extra_info={"event": "stats_error", "error": str(e)})
        return {"error": str(e), "system_health": {"status": "error"}}

@app.get("/api/findings")
def get_findings(repo: str = None, db: Session = Depends(database.get_db)):
    """
    Returns the top 10 most critical findings, optionally filtered by repo.
    Sorted by risk_score descending.
    """
    cache_key = f"dashboard_findings_{repo}" if repo else "dashboard_findings_global"

    # Step 1: Check cache (60 second TTL)
    if cache:
        cached_findings = cache.get(cache_key)
        if cached_findings:
            logger.info(f"Findings cache hit", extra_info={
                "event": "cache_hit",
                "key": cache_key,
                "endpoint": "findings"
            })
            return json.loads(cached_findings)

    # Step 2: Query database for top 10 riskiest findings
    import time
    query_start = time.time()
    logger.info(f"Findings cache miss", extra_info={
        "event": "cache_miss",
        "key": cache_key,
        "repo_filter": repo
    })
    
    query = db.query(models.Finding).join(models.Scan).filter(models.Scan.status == "completed")
    if repo:
        query = query.filter(models.Scan.project_name == repo)
        
    findings = query.order_by(models.Finding.risk_score.desc())\
        .limit(10)\
        .all()
    
    # Format findings for frontend display
    result = [
        {
            "id": f.id,
            "tool": f.tool,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "location": f"{f.file}:{f.line}",
            "verdict": f.ai_verdict,
            "project": f.scan.project_name,
            "ai_confidence": f.ai_confidence
        }
        for f in findings
    ]

    # Step 3: Cache result
    if cache:
        query_duration_ms = round((time.time() - query_start) * 1000, 2)
        cache.setex(cache_key, 60, json.dumps(result))
        logger.info(f"Findings cached", extra_info={
            "event": "cache_set",
            "key": cache_key,
            "rows_returned": len(result),
            "query_duration_ms": query_duration_ms
        })

    return result



@app.get("/api/projects")
def get_projects(db: Session = Depends(database.get_db)):
    """
    Returns list of projects with metadata for the carousel.
    """
    # Get all distinct project names
    project_names = [r[0] for r in db.query(models.Scan.project_name).distinct().all() if r[0]]
    
    results = []
    for name in project_names:
        # Get latest scan for provider info
        latest = db.query(models.Scan).filter(models.Scan.project_name == name).order_by(models.Scan.timestamp.desc()).first()
        
        # Check active
        is_active = db.query(models.Scan).filter(
            models.Scan.project_name == name,
            models.Scan.status.in_(["pending", "processing", "uploaded", "scanning", "analyzing", "queued", "scanning_queued"])
        ).count() > 0
        
        results.append({
            "name": name,
            "provider": latest.repo_provider or latest.ci_provider or "github",
            "is_active": is_active,
            "branch": latest.branch if latest else "main",
            "last_run": latest.timestamp.isoformat() if latest else None
        })
        
    return results

@app.get("/api/activity")
def get_activity(db: Session = Depends(database.get_db)):
    """
    Returns currently running scans.
    """
    # Active statuses: scanning, analyzing, pending, processing, uploaded
    active_scans = db.query(models.Scan).filter(
        models.Scan.status.in_(["pending", "processing", "uploaded", "scanning", "analyzing", "queued", "scanning_queued"]) 
    ).order_by(models.Scan.timestamp.desc()).all()
    
    return [
        {
            "id": s.id,
            "project": s.project_name,
            "provider": s.ci_provider,
            "status": s.status,
            "start_time": s.timestamp.isoformat(),
            "branch": s.branch or "main"
        }
        for s in active_scans
    ]

@app.get("/api/scan/{scan_id}/progress")
def get_scan_progress(scan_id: int):
    """
    Returns real-time progress for a specific scan from Redis.
    Used by frontend for live progress bar updates.
    """
    if not cache:
        return {"error": "Redis unavailable"}

    # Redis key format: scan:<id>:state (hash containing step info)
    redis_key = f"scan:{scan_id}:state"
    state = cache.hgetall(redis_key)
    
    # Return defaults if no state found (scan not yet started)
    if not state:
        return {
            "status": "unknown", 
            "progress_percent": 0, 
            "stage": "Initializing",
            "step_description": "Waiting for workers...",
            "step": 0,
            "total_steps": 10
        }

    # Calculate percentage from step/total
    try:
        step = int(state.get("step_number", 0))
        total = int(state.get("total_steps", 10))  # Default 10 to avoid div/0
        progress = round((step / total) * 100) if total > 0 else 0
    except ValueError:
        progress = 0

    return {
        "scan_id": scan_id,
        "status": state.get("status", "processing"),
        "stage": state.get("stage", "Processing"),
        "step_description": state.get("message", ""),
        "step": int(state.get("step_number", 0)),
        "total_steps": int(state.get("total_steps", 10)),
        "progress_percent": min(progress, 100)  # Cap at 100%
    }

@app.delete("/api/project")
def delete_project(repo: str, db: Session = Depends(database.get_db)):
    """
    Deletes a project and all its associated data (Scans, Findings) from DB and Cache.
    """
    if not repo:
        return {"error": "Repo name required"}

    logger.info(f"Deleting project: {repo}", extra_info={"event": "delete_project_start", "repo": repo})
    
    try:
        # 1. Find Scans
        scans = db.query(models.Scan).filter(models.Scan.project_name == repo).all()
        scan_ids = [s.id for s in scans]
        
        if not scan_ids:
            return {"message": "Project not found or already deleted"}

        # 2. Delete Findings (Cascade manually if needed, or rely on DB)
        # SQLAlchemy cascade might handle this, but explicit is safer for now
        db.query(models.Finding).filter(models.Finding.scan_id.in_(scan_ids)).delete(synchronize_session=False)
        
        # 3. Delete Scans
        db.query(models.Scan).filter(models.Scan.project_name == repo).delete(synchronize_session=False)
        
        # 4. Commit
        db.commit()
        
        # 5. Clean Cache
        if cache:
            cache.delete(f"dashboard_stats_{repo}")
            cache.delete(f"dashboard_findings_{repo}")
            # Optional: Clean individual scan keys if feasible, but TTL usually handles them
            for sid in scan_ids:
                cache.delete(f"scan:{sid}:state")
                
        logger.info(f"Project deleted: {repo}", extra_info={
            "event": "project_deleted",
            "project": repo,
            "scans_deleted": len(scan_ids),
            "cache_keys_cleared": 2 + len(scan_ids)
        })
        return {"status": "success", "message": f"Deleted {len(scan_ids)} scans for {repo}"}
        
    except Exception as e:
        db.rollback()
        logger.error(f"Delete failed: {e}", extra_info={"event": "delete_project_failed", "error": str(e)})
        return {"error": "Deletion failed", "details": str(e)}

# --- NEW ENDPOINTS FOR DASHBOARD OVERHAUL ---

@app.get("/api/findings/all")
def get_all_findings(
    page: int = 1,
    per_page: int = 15,
    repo: str = None,
    tool: str = None,
    severity: str = None,
    db: Session = Depends(database.get_db)
):
    """
    Returns paginated list of all findings with optional filters.
    Used by the new dashboard findings table.
    """
    query = db.query(models.Finding).join(models.Scan).filter(models.Scan.status == "completed")
    
    # Apply filters
    if repo:
        query = query.filter(models.Scan.project_name == repo)
    if tool:
        query = query.filter(models.Finding.tool == tool)
    if severity:
        query = query.filter(models.Finding.severity == severity)
    
    # Get total count
    total = query.count()
    
    # Paginate
    offset = (page - 1) * per_page
    findings = query.order_by(models.Finding.risk_score.desc())\
        .offset(offset)\
        .limit(per_page)\
        .all()
    
    # Format for frontend
    result = [
        {
            "id": f.id,
            "tool": f.tool,
            "severity": f.severity,
            "risk_score": f.risk_score,
            "location": f"{f.file}:{f.line}" if f.file else "-",
            "project": f.scan.project_name,
            "ai_confidence": f.ai_confidence,
            "ai_verdict": f.ai_verdict,
            "has_fix": f.remediation_patch is not None and len(f.remediation_patch.strip()) > 0 if f.remediation_patch else False
        }
        for f in findings
    ]
    
    return {
        "findings": result,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page
    }

@app.get("/api/finding/{finding_id}")
def get_finding_detail(finding_id: int, db: Session = Depends(database.get_db)):
    """
    Returns full details of a single finding, including AI reasoning and patch.
    Used for the AI Fix diff modal.
    """
    finding = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    
    if not finding:
        return {"error": "Finding not found"}
    
    return {
        "id": finding.id,
        "tool": finding.tool,
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "risk_score": finding.risk_score,
        "file": finding.file,
        "line": finding.line,
        "message": finding.message,
        "snippet": finding.snippet,
        "ai_verdict": finding.ai_verdict,
        "ai_confidence": finding.ai_confidence,
        "ai_reasoning": finding.ai_reasoning,
        "remediation_patch": finding.remediation_patch,
        "pr_url": finding.pr_url,
        "project": finding.scan.project_name if finding.scan else None,
        "created_at": finding.created_at.isoformat() if finding.created_at else None
    }

@app.get("/api/filters")
def get_filter_options(db: Session = Depends(database.get_db)):
    """
    Returns distinct values for filter dropdowns (repos, tools, severities).
    """
    # Get distinct repos
    repos = db.query(models.Scan.project_name).distinct().all()
    repos = [r[0] for r in repos if r[0]]
    
    # Get distinct tools
    tools = db.query(models.Finding.tool).distinct().all()
    tools = [t[0] for t in tools if t[0]]
    
    # Get distinct severities
    severities = db.query(models.Finding.severity).distinct().all()
    severities = [s[0] for s in severities if s[0]]
    # Order severities logically
    severity_order = ["Critical", "High", "Medium", "Low"]
    severities = sorted(severities, key=lambda x: severity_order.index(x) if x in severity_order else 999)
    
    return {
        "repos": sorted(repos),
        "tools": sorted(tools),
        "severities": severities
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)

