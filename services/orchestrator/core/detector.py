"""
Application Stack Detection Module.

Provides heuristics for detecting the technology stack of a source code project.
This information is used to:
1. Determine the appropriate Docker image for sandbox execution.
2. Generate correct build/run commands for DAST testing.
3. Identify framework-specific ports and entry points.

Supported Languages/Frameworks:
    - Python: Flask, FastAPI, Django
    - Node.js: Express, NestJS
    - Go: Standard library, Gin, etc.
    - Java: Maven/Spring Boot
    - PHP: Composer/Laravel
"""

import os
import re
import json
from typing import Dict, Any
from .utils import find_entry_point

def detect_application_stack(source_path: str) -> Dict[str, Any]:
    """
    Analyzes the source code directory to detect the application stack,
    framework, and potential usage details (port, start command).
    
    Returns:
        Dict: {
            "type": "web" | "library" | "unknown",
            "framework": "fastapi" | "flask" | "express" | "django" | ...,
            "language": "python" | "node" | "go" | "java",
            "port": 8080 (int),
            "start_command": "python app.py" (str),
            "detected": True/False
        }
    """
    result = {
        "type": "unknown",
        "framework": None,
        "language": None,
        "port": None,
        "start_command": None,
        "detected": False
    }

    # 1. Detect Dockerfile (Highest Confidence for Port/Cmd)
    dockerfile_path = os.path.join(source_path, "Dockerfile")
    if os.path.exists(dockerfile_path):
        _parse_dockerfile(dockerfile_path, result)

    # 2. Detect Language & Helper Files
    if os.path.exists(os.path.join(source_path, "requirements.txt")):
        result["language"] = "python"
        _analyze_python(source_path, result)
        
    elif os.path.exists(os.path.join(source_path, "package.json")):
        result["language"] = "node"
        _analyze_node(source_path, result)
        
    elif os.path.exists(os.path.join(source_path, "main.go")) or os.path.exists(os.path.join(source_path, "go.mod")):
        result["language"] = "go"
        
    # 3. Heuristics for Port if not found
    if not result["port"]:
        if result["framework"] == "flask": result["port"] = 5000
        elif result["framework"] == "fastapi": result["port"] = 8000
        elif result["framework"] == "django": result["port"] = 8000
        elif result["framework"] == "express": result["port"] = 3000
        elif result["language"] == "java": result["port"] = 8080
        
    # 4. Infer Type
    if result["framework"] or result["port"]:
        result["type"] = "web"
        result["detected"] = True
        
    return result

def _parse_dockerfile(path: str, result: Dict[str, Any]) -> None:
    """
    Extracts port configuration from an existing Dockerfile.
    
    Args:
        path: Absolute path to the Dockerfile.
        result: Detection result dictionary to update in-place.
    """
    with open(path, "r") as f:
        content = f.read()
        
    # Extract EXPOSE
    expose_match = re.search(r"EXPOSE\s+(\d+)", content, re.IGNORECASE)
    if expose_match:
        result["port"] = int(expose_match.group(1))

def _analyze_python(path: str, result: Dict[str, Any]) -> None:
    """
    Analyzes a Python project to detect framework and entry point.
    
    Inspects requirements.txt for framework dependencies (Flask, FastAPI, Django)
    and searches for common entry point files to determine the start command.
    
    Args:
        path: Absolute path to the source directory.
        result: Detection result dictionary to update in-place.
    """
    req_path = os.path.join(path, "requirements.txt")
    if os.path.exists(req_path):
        with open(req_path, "r") as f:
            reqs = f.read().lower()
            if "flask" in reqs: result["framework"] = "flask"
            elif "fastapi" in reqs: result["framework"] = "fastapi"
            elif "django" in reqs: result["framework"] = "django"
            
    # Try to find app.run or uvicorn
    entry_file = find_entry_point(path, "python")
            
    # 2. If found, check content for specific runners
    if entry_file:
        with open(os.path.join(path, entry_file), "r", errors="ignore") as f:
            content = f.read()
            if "uvicorn.run" in content:
                result["start_command"] = f"python3 {entry_file}"
            elif "app.run" in content:
                result["start_command"] = f"python3 {entry_file}"
            elif 'if __name__ == "__main__":' in content:
                 result["start_command"] = f"python3 {entry_file}"
            
    # Fallback if we found a file but no explicit run command detected
    if entry_file and not result["start_command"]:
         result["start_command"] = f"python3 {entry_file}" 

def _analyze_node(path: str, result: Dict[str, Any]) -> None:
    """
    Analyzes a Node.js project to detect framework and start script.
    
    Parses package.json to identify framework dependencies (Express, NestJS)
    and extracts the npm start script if defined.
    
    Args:
        path: Absolute path to the source directory.
        result: Detection result dictionary to update in-place.
    """
    pkg_path = os.path.join(path, "package.json")
    try:
        with open(pkg_path, "r") as f:
            data = json.load(f)
            deps = data.get("dependencies", {})
            if "express" in deps: result["framework"] = "express"
            if "nestjs" in deps: result["framework"] = "nest"
            
            scripts = data.get("scripts", {})
            if "start" in scripts:
                result["start_command"] = f"npm start"
    except:
        pass
