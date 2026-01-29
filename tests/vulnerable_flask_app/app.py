from flask import Flask, request, render_template_string
import os
import sqlite3

app = Flask(__name__)

# Vulnerable Home Page
@app.route('/')
def home():
    return """
    <h1>Vulnerable DAST Test App</h1>
    <ul>
        <li><a href="/xss?q=hello">XSS Test (Reflected)</a></li>
        <li><a href="/sqli?username=admin">SQL Injection Test</a></li>
        <li><a href="/cmd?ip=127.0.0.1">Command Injection Test</a></li>
    </ul>
    """

# 1. Reflected XSS Vulnerability
# DAST should detect this by injecting <script> tags.
@app.route('/xss')
def xss():
    query = request.args.get('q', '')
    # VULNERABILITY: No input sanitization, reflected directly in response
    return f"<h1>Search Results for: {query}</h1>"

# 2. SQL Injection Vulnerability
# DAST should detect this by injecting SQL characters.
@app.route('/sqli')
def sqli():
    username = request.args.get('username', '')
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES ('admin', 'secret123')")
    
    # VULNERABILITY: F-string SQL construction
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        return f"User Found: {user}" if user else "User Not Found"
    except Exception as e:
        return f"Database Error: {e}", 500

# 3. Command Injection Vulnerability
# DAST should detect this by injecting shell operators (; | &&).
@app.route('/cmd')
def cmd():
    ip = request.args.get('ip', '127.0.0.1')
    # VULNERABILITY: User input passed directly to shell
    stream = os.popen(f"ping -c 1 {ip}")
    output = stream.read()
    return f"<pre>{output}</pre>"

if __name__ == '__main__':
    # Run slightly unsafe to allow external connections for DAST
    app.run(host='0.0.0.0', port=5000)
