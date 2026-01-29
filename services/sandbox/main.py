"""
Sandbox Service Entry Point.

This service provides an isolated environment for safe execution of code.
It is used to:
1. Verify generated fixes by running them in a clean container.
2. Execute 'Red Team' attacks (PoC exploits) to validate vulnerabilities.
It exposes HTTP endpoints to trigger these operations.
"""

import threading
import os
import traceback
from fastapi import FastAPI, HTTPException
from common.core.logger import get_logger
from common.core.queue import StateManager
from pydantic import BaseModel
from typing import Dict, Any, Optional

# Core Logic Imports
from core.red_team import run_red_team_attack
from core.sandbox import verify_patch_in_sandbox, verify_poc

app = FastAPI(title="Sandbox Service")
logger = get_logger(__name__)

class RedTeamRequest(BaseModel):
    finding: Dict[str, Any]
    project: str
    source_path: str = "."

class VerifyPatchRequest(BaseModel):
    source_path: str
    patch_code: str
    target_file: str

class VerifyPocRequest(BaseModel):
    source_path: str
    poc_code: str
    file_extension: str

class DeployRequest(BaseModel):
    source_path: str
    port: int
    image: Optional[str] = None
    start_cmd: Optional[str] = None

@app.post("/red_team")
def trigger_red_team_http(req: RedTeamRequest):
    """
    HTTP endpoint to execute a Red Team PoC attack.
    """
    import time
    start_time = time.time()
    finding_id = req.finding.get('id')
    vulnerability_type = req.finding.get('rule_id', 'unknown')
    
    logger.info(f"Red team attack request: {req.project}", extra_info={
        "event": "red_team_request",
        "project": req.project,
        "finding_id": finding_id,
        "vulnerability_type": vulnerability_type
    })
    
    try:
        result = run_red_team_attack(req.finding, req.project, req.source_path)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        
        logger.info(f"Red team attack completed: {req.project}", extra_info={
            "event": "red_team_completed",
            "project": req.project,
            "finding_id": finding_id,
            "success": result.get('success', False),
            "duration_ms": duration_ms
        })
        return result
    except Exception as e:
        logger.error(f"Red Team Attack Failed: {e}", extra_info={
            "event": "red_team_failed",
            "error": str(e),
            "project": req.project,
            "finding_id": finding_id
        })
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify_patch")
def trigger_verify_patch_http(req: VerifyPatchRequest):
    """
    HTTP endpoint to verify a patch in the sandbox.
    """
    import time
    start_time = time.time()
    
    logger.info(f"Patch verification request: {req.target_file}", extra_info={
        "event": "patch_verification_request",
        "target_file": req.target_file,
        "patch_size": len(req.patch_code) if req.patch_code else 0
    })
    
    try:
        success, output = verify_patch_in_sandbox(req.source_path, req.patch_code, req.target_file)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        
        logger.info(f"Patch verification completed", extra_info={
            "event": "patch_verification_completed",
            "target_file": req.target_file,
            "success": success,
            "duration_ms": duration_ms
        })
        return {"success": success, "output": output}
    except Exception as e:
        logger.error(f"Patch Verification Failed: {e}", extra_info={
            "event": "patch_verification_failed",
            "error": str(e),
            "target_file": req.target_file
        })
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify_poc")
def trigger_verify_poc_http(req: VerifyPocRequest):
    """
    HTTP endpoint to verify a standalone PoC script.
    """
    import time
    start_time = time.time()
    
    logger.info(f"PoC verification request", extra_info={
        "event": "poc_verification_request",
        "file_extension": req.file_extension,
        "poc_size": len(req.poc_code) if req.poc_code else 0
    })
    
    try:
        success, output = verify_poc(req.source_path, req.poc_code, req.file_extension)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        
        logger.info(f"PoC verification completed", extra_info={
            "event": "poc_verification_completed",
            "file_extension": req.file_extension,
            "success": success,
            "duration_ms": duration_ms
        })
        return {"success": success, "output": output}
    except Exception as e:
        logger.error(f"PoC Verification Failed: {e}", extra_info={
            "event": "poc_verification_failed",
            "error": str(e)
        })
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/deploy")
def trigger_deploy_http(req: DeployRequest):
    """
    HTTP endpoint to deploy the application for DAST.
    """
    import time
    start_time = time.time()
    from core.sandbox import deploy_application
    
    logger.info(f"Deploy request: port {req.port}", extra_info={
        "event": "deploy_request",
        "source_path": req.source_path,
        "port": req.port,
        "image": req.image
    })
    
    try:
        result = deploy_application(req.source_path, req.port, req.image, req.start_cmd)
        duration_ms = round((time.time() - start_time) * 1000, 2)
        
        logger.info(f"Deploy completed: port {req.port}", extra_info={
            "event": "deploy_completed",
            "port": req.port,
            "container_id": result.get('container_id'),
            "duration_ms": duration_ms
        })
        return result
    except Exception as e:
         logger.error(f"Deploy Failed: {e}", extra_info={
             "event": "deploy_failed",
             "error": str(e),
             "port": req.port
         })
         raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "ok", "mode": "http_api"}

@app.on_event("startup")
async def startup_event():
    logger.info("Sandbox Service HTTP API Started", extra_info={"event": "startup_complete"})
