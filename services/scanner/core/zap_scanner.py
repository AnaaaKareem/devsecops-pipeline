"""
ZAP Scanner Integration.

This module provides an interface to OWASP ZAP for DAST scanning.
It orchestrates the ZAP API to:
1. Start a spider scan to discover URLs.
2. Wait for passive scanning to complete.
3. Retrieve all security alerts and format them as findings.

Requires ZAP to be running and accessible at ZAP_URL.
"""

import time
import requests
import uuid
import logging
from common.core.logger import get_logger

logger = get_logger(__name__)

# ZAP API base URL (assumes ZAP is running as a sidecar)
ZAP_URL = "http://zap:8080"

def start_zap_scan(target_url: str, project: str) -> dict:
    """
    Executes a ZAP DAST scan against the target URL.
    
    Args:
        target_url: The URL to scan (must be accessible from ZAP container).
        project: Project name for logging purposes.
        
    Returns:
        Dictionary with 'findings' list on success, or 'error' key on failure.
    """
    scan_id = str(uuid.uuid4())[:8]  # Unique ID for logging
    logger.info(f"Starting ZAP API scan for {target_url} (ID: {scan_id})")
    
    try:
        # Step 1: Start Spider to discover URLs
        logger.info(f"[ZAP] Starting Spider for {target_url}")
        res = requests.get(f"{ZAP_URL}/JSON/spider/action/scan/", params={'url': target_url, 'recurse': 'true'}, timeout=10)
        try:
            res_json = res.json()
        except Exception:
            return {"error": f"Failed to start spider (invalid JSON): {res.text}"}
            
        if 'scan' not in res_json:
             return {"error": f"Failed to start spider: {res_json}"}
        
        spider_id = res_json['scan']
        logger.info(f"[ZAP] Spider started with ID: {spider_id}")
        
        # Step 2: Poll spider status until complete (max 1 minute)
        max_retries = 30
        while max_retries > 0:
            time.sleep(2)
            try:
                status_res = requests.get(f"{ZAP_URL}/JSON/spider/view/status/", params={'scanId': spider_id}, timeout=10)
                status = int(status_res.json().get('status', -1))
                logger.info(f"[ZAP] Spider Status: {status}%")
                if status >= 100:
                    break  # Spider complete
            except Exception as e:
                logger.warning(f"[ZAP] Error polling spider: {e}")
            max_retries -= 1
        
        if max_retries <= 0:
            logger.warning("[ZAP] Spider timed out, proceeding anyway.")

        # Step 3: Wait for passive scan to process all requests
        logger.info("[ZAP] Waiting for Passive Scan to complete...")
        max_pscan_wait = 30  # Max 1 minute
        while max_pscan_wait > 0:
            time.sleep(2)
            try:
                pscan_res = requests.get(f"{ZAP_URL}/JSON/pscan/view/recordsToScan/", timeout=10)
                records = int(pscan_res.json().get('recordsToScan', -1))
                logger.info(f"[ZAP] Passive Scan Records Left: {records}")
                if records <= 0:
                    break  # All records processed
            except Exception as e:
                logger.warning(f"[ZAP] Error checking passive scan: {e}")
            max_pscan_wait -= 1

        # Step 4: Retrieve all alerts from ZAP
        logger.info("[ZAP] Retrieving Alerts...")
        alerts_res = requests.get(f"{ZAP_URL}/JSON/core/view/alerts/", params={'baseurl': target_url}, timeout=30)
        alerts = alerts_res.json().get('alerts', [])
        
        # Format findings to match our schema
        findings = []
        for alert in alerts:
            findings.append({
                "tool": "ZAP",
                "rule_id": alert.get('pluginId'),
                "severity": alert.get('risk'),
                "message": f"{alert.get('name')}: {alert.get('description')}",
                # "description": alert.get('description'), # Model does not have description field
                "file": alert.get('url'), # Use URL as file
                "line": 0,
                "dast_endpoint": alert.get('method') + " " + alert.get('url'),
                "snippet": alert.get('param', '') 
            })
            
        logger.info(f"[ZAP] Found {len(findings)} alerts.")
        return {"findings": findings, "raw_alerts": alerts}

    except Exception as e:
        logger.error(f"ZAP API Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {"error": str(e)}
