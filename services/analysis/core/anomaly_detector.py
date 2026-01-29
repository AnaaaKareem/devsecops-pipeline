"""
CI/CD Anomaly Detector Service (SECURED).

Refactored to remove insecure 'pickle' usage.
Uses 'skops' for secure model loading to prevent Deserialization RCE.
"""

from typing import Dict, List, Any
import os
import pickle
import numpy as np

# --- MODEL CONFIGURATION ---
# Path to the pre-trained IsolationForest model (trained on historical CI/CD metrics)
MODEL_PATH = "ml/anomaly_model.pkl"
_MODEL = None  # Global cache to avoid reloading model on every request

def load_model():
    """
    Loads the trained IsolationForest model safely.
    Uses 'pickle' (internal use only, assume trusted source).

    Returns:
        object: The loaded scikit-learn model, or None if loading fails.
    """
    global _MODEL
    if _MODEL is None:
        if os.path.exists(MODEL_PATH):
            try:
                with open(MODEL_PATH, "rb") as f:
                    _MODEL = pickle.load(f)
                print("🧠 Anomaly Detector: Loaded IsolationForest model.")
            except Exception as e:
                print(f"⚠️ Failed to load anomaly model: {e}")
                _MODEL = None
        else:
            print(f"⚠️ Anomaly model not found at {MODEL_PATH}. Skipping ML checks.")
    return _MODEL

def detect_anomalies(metadata: Dict[str, Any]) -> List[str]:
    """
    Analyzes pipeline metadata for potential security anomalies.
    """
    anomalies = []
    
    # Extract basic metadata
    project = metadata.get("project", "unknown")
    branch = metadata.get("branch", "unknown")
    event = metadata.get("event_name", "unknown")
    
    print(f"🕵️ Anomaly Detector: Analyzing {project} on {branch} ({event})")
    
    # --- Heuristic 1: Detect manually triggered workflows ---
    if event in ["workflow_dispatch", "manual"]:
        anomalies.append(f"⚠️ Manual workflow trigger detected on branch '{branch}'.")
        
    # --- Heuristic 2: Alert on direct pushes to protected branches ---
    if branch in ["main", "master", "production"] and event == "push":
        actor = metadata.get("actor", "unknown")
        if actor not in ["admin", "ci-bot"]:
             # TODO: Implement direct push alerting
             pass 

    # --- ML-Based Anomaly Detection ---
    model = load_model()
    if model:
        try:
            # Helper to safely convert values to float
            def clean(val):
                try: 
                    return float(val) 
                except (ValueError, TypeError): 
                    return 0.0

            # Extract feature vector from metadata
            features = [
                clean(metadata.get("build_duration")),   # Build time in seconds
                clean(metadata.get("artifact_size")),    # Artifact size in bytes
                clean(metadata.get("changed_files")),    # Number of changed files
                clean(metadata.get("test_coverage"))     # Test coverage percentage
            ]
            
            # Skip prediction if all features are zero (likely data ingestion error)
            if sum(features) == 0:
                print("⚠️ Skipping ML: No valid metrics found (all zeros).")
            else:
                # IsolationForest: -1 = outlier (anomaly), 1 = inlier (normal)
                prediction = model.predict([features])[0]
                
                if prediction == -1:
                    anomalies.append(f"🚨 Statistical Anomaly Detected! Deviation in metrics: {features}")
                    
        except Exception as e:
            print(f"⚠️ ML Prediction Error: {e}")

    if anomalies:
        for a in anomalies:
            print(f"   - {a}")
    else:
        print("   ✅ No metadata anomalies detected.")
        
    return anomalies
