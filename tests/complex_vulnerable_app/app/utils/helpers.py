import os
import pickle
import base64

def check_ping(host):
    """
    Helper to ping a host.
    VULNERABLE: Passes input directly to shell.
    """
    # Vulnerability is here, called by routes/files.py
    stream = os.popen(f"ping -c 1 {host}")
    return stream.read()

def deserialize_data(data_str):
    """
    Helper to deserialize user preference data.
    VULNERABLE: Insecure Deserialization.
    """
    try:
        # VULNERABILITY: pickle.loads is unsafe
        data_bytes = base64.b64decode(data_str)
        return pickle.loads(data_bytes)
    except:
        return {}
