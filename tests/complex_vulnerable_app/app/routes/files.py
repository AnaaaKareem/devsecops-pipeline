from flask import Blueprint, request
import os
import subprocess
from app.utils import helpers

bp = Blueprint('files', __name__, url_prefix='/files')

@bp.route('/read')
def read_file():
    filename = request.args.get('path', 'test.txt')
    
    # VULNERABILITY: Path Traversal
    # Allows reading /etc/passwd if not sanitized
    try:
        # Simulate reading a file (mocked for safety in this demo context)
        # In a real vulnerability, this would be open(filename).read()
        return f"Reading file content at: {os.path.abspath(filename)}"
    except Exception as e:
        return str(e)

@bp.route('/status')
def status():
    host = request.args.get('host', '127.0.0.1')
    
    # VULNERABILITY: Command Injection
    # Using a helper function to show cross-file tracing
    result = helpers.check_ping(host)
    return f"<pre>{result}</pre>"
