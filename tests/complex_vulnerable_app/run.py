from flask import Flask
from app.routes import auth, user, files

app = Flask(__name__)

# Register Blueprints for modular structure
app.register_blueprint(auth.bp)
app.register_blueprint(user.bp)
app.register_blueprint(files.bp)

@app.route('/')
def index():
    return """
    <h1>Complex Vulnerable App</h1>
    <p>Modular Flask Application with Security Flaws</p>
    <ul>
        <li><a href="/auth/login?username=admin">Auth (SQLi)</a></li>
        <li><a href="/user/profile?bio=Hello">Profile (XSS)</a></li>
        <li><a href="/files/read?path=etc/passwd">Files (Path Traversal)</a></li>
        <li><a href="/files/status?host=127.0.0.1">Network Status (Cmd Injection)</a></li>
    </ul>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
