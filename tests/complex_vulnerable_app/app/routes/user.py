from flask import Blueprint, request, render_template_string

bp = Blueprint('user', __name__, url_prefix='/user')

@bp.route('/profile')
def profile():
    bio = request.args.get('bio', 'Default Bio')
    
    # VULNERABILITY: Reflected XSS (No sanitization)
    template = f"""
    <h1>User Profile</h1>
    <p>Bio: {bio}</p>
    """
    return render_template_string(template)
