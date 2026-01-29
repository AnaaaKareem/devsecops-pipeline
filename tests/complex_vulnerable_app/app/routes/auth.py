from flask import Blueprint, request
import sqlite3

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/login')
def login():
    username = request.args.get('username', '')
    
    # SETUP DB (Ephemeral)
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'SuperSecretPass')")
    
    # VULNERABILITY: SQL Injection via f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            return f"Welcome back, {user[1]}! Your secret is: {user[2]}"
        return "Login Failed"
    except Exception as e:
        return f"SQL Error: {e}"
