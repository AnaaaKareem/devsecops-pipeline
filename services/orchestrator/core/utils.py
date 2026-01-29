"""
Orchestrator Utility Functions.

Provides helper utilities for the Orchestrator service, including
functions for locating application entry points in source code.
"""

import os
from typing import Optional


def find_entry_point(source_path: str, language: str) -> Optional[str]:
    """
    Searches for a valid application entry point file in the source directory.
    
    Looks for common entry point filenames (e.g., main.py, app.py, server.js)
    first in the root directory, then recursively through subdirectories,
    skipping common non-source directories.
    
    Args:
        source_path: Absolute path to the source code directory.
        language: Programming language ("python" or "node").
        
    Returns:
        Relative path to the entry point file (e.g., "src/main.py"),
        or None if no entry point is found.
    """
    candidates = []
    if language == "python":
        candidates = ["main.py", "app.py", "wsgi.py", "server.py", "manage.py", "run.py"]
    elif language == "node":
        candidates = ["server.js", "app.js", "index.js", "main.js"]

    # 1. Check root first (Priority)
    for c in candidates:
        if os.path.exists(os.path.join(source_path, c)):
            return c

    # 2. Recursive search (if not found in root)
    for root, dirs, files in os.walk(source_path):
        # Skip common non-source dirs to speed up
        if any(x in root for x in ["node_modules", "venv", ".git", "__pycache__"]):
            continue
        
        for file in files:
            if file in candidates:
                rel_path = os.path.relpath(os.path.join(root, file), source_path)
                return rel_path
    
    return None
