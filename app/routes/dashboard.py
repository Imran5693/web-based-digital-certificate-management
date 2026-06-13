from flask import Blueprint, render_template, session, redirect, url_for, flash, request  # 🎯 ADD 'request' import
from app import db
from app.models import CertificateAction, User
from app.routes.auth import ldap_get_all_users
from app.models import Certificate

dashboard_bp = Blueprint('dashboard', __name__)

def login_required(f):
    """Custom login required decorator"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please login first", "warning")
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Custom admin required decorator"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash("Please login first", "warning")
            return redirect(url_for('auth.login', next=request.url))
        if not session.get('is_admin'):
            flash("Admin access required", "danger")
            return redirect(url_for('dashboard.user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- USER DASHBOARD ----------------------
@dashboard_bp.route('/user/dashboard')
def user_dashboard():
    if 'username' not in session:
        flash("Please login first", "warning")
        return redirect(url_for('auth.login', next=url_for('dashboard.user_dashboard')))

    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        flash("User not found!", "danger")
        session.clear()
        return redirect(url_for('auth.login'))

    certs = Certificate.query.filter_by(user_id=user.id).order_by(Certificate.created_at.desc()).all()

    return render_template('user/user_dashboard.html', username=user.username, certs=certs)

# ---------------------- ADMIN DASHBOARD ----------------------
@dashboard_bp.route('/admin/dashboard')
def admin_dashboard():
    if 'username' not in session:
        flash("Please login first", "warning")
        return redirect(url_for('auth.login', next=url_for('dashboard.admin_dashboard')))
    
    if not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for('dashboard.user_dashboard'))

    # ----------------- LDAP users -----------------
    ldap_users = ldap_get_all_users()  # Returns list of dicts: username, full_name, email
    db_users = {u.username: u for u in User.query.all()}

    merged_users = []
    for u in ldap_users:
        username = u['username']
        merged_users.append({
            'username': username,
            'full_name': u['full_name'],
            'email': u['email'],
            'is_admin': db_users.get(username).is_admin if username in db_users else False,
            'role': db_users.get(username).role if username in db_users else 'user'
        })

    total_users = len(merged_users)
    total_admins = sum(1 for u in merged_users if u['is_admin'])
    total_standard = total_users - total_admins

    # ----------------- Certificates -----------------
    total_certs = Certificate.query.count()
    generated_certs = Certificate.query.filter_by(generated_by_admin=True).count()
    pending_csrs = Certificate.query.filter_by(status="Pending").count()
    recent_certs = Certificate.query.order_by(Certificate.created_at.desc()).limit(10).all()

    return render_template(
        'admin/dashboard.html',
        total_users=total_users,
        total_admins=total_admins,
        total_standard=total_standard,
        total_certs=total_certs,
        generated_certs=generated_certs,
        pending_csrs=pending_csrs,
        recent_certs=recent_certs
    )

from app.models import CertificateAction, SystemAuditLog

@dashboard_bp.route('/admin/audit')
@admin_required
def admin_audit():
    # Fetch last 100 certificate actions
    cert_actions = CertificateAction.query.order_by(CertificateAction.action_timestamp.desc()).limit(100).all()
    # Fetch last 100 system/user actions
    user_actions = SystemAuditLog.query.order_by(SystemAuditLog.action_timestamp.desc()).limit(100).all()

    # Merge and sort by timestamp descending
    all_actions = sorted(cert_actions + user_actions, key=lambda x: x.action_timestamp, reverse=True)

    # Add target_name property for template uniformity
    for act in all_actions:
        if isinstance(act, CertificateAction):
            act.target_name = getattr(act.certificate, 'common_name', '-') if act.certificate else '-'
        else:
            act.target_name = getattr(act, 'target_name', '-') or '-'

    return render_template('admin/audit.html', actions=all_actions)
