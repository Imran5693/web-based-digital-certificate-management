from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app import db
from app.models import User, SystemAuditLog
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, MODIFY_ADD
from app.config import Config
from app.utils.stepca_utils import check_stepca_status
from app.utils.ldap_utils import check_ldap_status


auth_bp = Blueprint('auth', __name__)

# -------------------- LDAP Helper Functions --------------------
def ldap_connect():
    """
    Connect to LDAP using admin credentials for user management.
    """
    server = Server(Config.LDAP_URI, get_info=ALL)
    conn = Connection(
        server,
        user=Config.LDAP_ADMIN_DN,
        password=Config.LDAP_ADMIN_PASSWORD,
        auto_bind=True
    )
    return conn

def ldap_authenticate_user(username, password):
    """
    Authenticate user against LDAP.
    Returns: (success: bool, message: str, is_admin: bool)
    """
    user_dn = f"uid={username},ou=users,dc=stepca,dc=local"
    server = Server(Config.LDAP_URI, get_info=ALL)
    try:
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        # check if user belongs to CAAdmins group
        admin_conn = ldap_connect()
        admin_conn.search(
            search_base="ou=groups,dc=stepca,dc=local",
            search_filter=f"(&(cn=CAAdmins)(member={user_dn}))",
            search_scope=SUBTREE,
            attributes=['cn']
        )
        is_admin = True if admin_conn.entries else False
        return True, "Authenticated successfully", is_admin
    except Exception as e:
        # distinguish between wrong password and user not found
        check_conn = ldap_connect()
        check_conn.search(
            search_base="ou=users,dc=stepca,dc=local",
            search_filter=f"(uid={username})",
            search_scope=SUBTREE,
            attributes=['uid']
        )
        if not check_conn.entries:
            return False, "User not found in LDAP", False
        else:
            return False, "Incorrect password", False

def ldap_create_user(username, password, full_name=None, role='user'):
    """
    Create a new user in LDAP and return success status.
    role: 'admin' or 'user'
    """
    try:
        conn = ldap_connect()
        # Generate next available UID
        conn.search('ou=users,dc=stepca,dc=local', '(objectClass=posixAccount)', SUBTREE, attributes=['uidNumber'])
        existing_uids = [int(e.uidNumber.value) for e in conn.entries if e.uidNumber.value]
        uid_number = max(existing_uids) + 1 if existing_uids else 1000

        # Choose gid based on role
        if role == 'admin':
            gid_number = 1001  # CAAdmins
            group_dn = "cn=CAAdmins,ou=groups,dc=stepca,dc=local"
        else:
            gid_number = 1002  # CAUsers
            group_dn = "cn=CAUsers,ou=groups,dc=stepca,dc=local"

        dn = f"uid={username},ou=users,dc=stepca,dc=local"
        attributes = {
            'objectClass': ['inetOrgPerson', 'posixAccount', 'top'],
            'cn': full_name or username,
            'sn': username,
            'uid': username,
            'uidNumber': uid_number,
            'gidNumber': gid_number,
            'homeDirectory': f"/home/{username}",
            'loginShell': "/bin/bash",
            'userPassword': password
        }

        # Add user
        if conn.add(dn, attributes=attributes):
            # Also add to corresponding group
            conn.modify(group_dn, {'member': [(MODIFY_ADD, [dn])]})
            return True, "success"
        else:
            if 'entryAlreadyExists' in str(conn.result):
                return False, "exists"
            else:
                return False, str(conn.result)
    except Exception as e:
        return False, str(e)

def ldap_delete_user(username):
    """
    Delete user from LDAP
    """
    try:
        conn = ldap_connect()
        dn = f"uid={username},ou=users,dc=stepca,dc=local"
        if conn.delete(dn):
            return True, "success"
        else:
            return False, str(conn.result)
    except Exception as e:
        return False, str(e)

def ldap_get_all_users():
    """
    Fetch all users from LDAP
    """
    conn = ldap_connect()
    conn.search('ou=users,dc=stepca,dc=local', '(objectClass=inetOrgPerson)', SUBTREE,
                attributes=['uid', 'cn', 'mail'])
    users = []
    for entry in conn.entries:
        users.append({
            'username': entry.uid.value,
            'full_name': entry.cn.value,
            'email': entry.mail.value if 'mail' in entry else f"{entry.uid.value}@example.com"
        })
    return users

# -------------------- Routes --------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    stepca_online = check_stepca_status()
    ldap_online = check_ldap_status()    

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        success, message, is_admin = ldap_authenticate_user(username, password)

        if success:
            session.permanent = True
            session['username'] = username
            session['is_admin'] = is_admin

            # ✅ Guarded insert
            existing_user = User.query.filter_by(username=username).first()
            if not existing_user:
                existing_user = User(
                    username=username,
                    is_admin=is_admin,
                    role="admin" if is_admin else "user"
                )
                db.session.add(existing_user)
                db.session.commit()

            session['user_id'] = existing_user.id

            # Audit log
            db.session.add(SystemAuditLog(
                user_id=existing_user.id,
                action_type="login",
                ip_address=request.remote_addr
            ))
            db.session.commit()

            flash("Login successful", "success")
            return redirect(url_for('dashboard.admin_dashboard' if is_admin else 'dashboard.user_dashboard'))
        else:
            flash(message, "danger")

    return render_template('login.html', stepca_online=stepca_online, ldap_online=ldap_online)


@auth_bp.route('/admin/add-user', methods=['GET', 'POST'])
def add_user():
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', 'user')
        is_admin = role == 'admin'

        if not username or not password:
            flash("Username and password are required!", "warning")
            return render_template('admin/add_user.html')

        # Create user in LDAP
        success, result = ldap_create_user(username, password, role=role)

        if success:
            # Save in local DB
            new_user = User(
                username=username,
                is_admin=is_admin,
                role=role
            )
            db.session.add(new_user)
            db.session.commit()

            # SYSTEM AUDIT LOG (CORRECT PLACE)
            audit_log = SystemAuditLog(
                user_id=session['user_id'],  # admin who created the user
                action_type="user_created",
                ip_address=request.remote_addr
            )
            db.session.add(audit_log)
            db.session.commit()

            flash(f"User '{username}' created successfully!", "success")
            return redirect(url_for('auth.user_management'))

        else:
            if result == "exists":
                flash(f"User '{username}' already exists.", "warning")
            else:
                flash(f"Error creating user: {result}", "danger")

    return render_template('admin/add_user.html')



@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    stepca_online = check_stepca_status()  # returns True/False
    ldap_online = check_ldap_status() 

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        full_name = request.form.get('full_name', username).strip()  # default to username if not provided

        if not username or not password:
            flash("Username and password required!", "warning")
            return render_template('register_public.html')

        success, result = ldap_create_user(username, password, full_name=full_name, role='user')
        if success:
            # Save in local DB as normal user
            new_user = User(username=username, is_admin=False, role='user')
            db.session.add(new_user)
            db.session.commit()

            
            db.session.add(SystemAuditLog(
                user_id=None,
                action_type="public_user_registered",
                ip_address=request.remote_addr
                ))
            db.session.commit()

            flash(f"Account '{username}' created successfully! Please login.", "success")
            return redirect(url_for('auth.login'))
        else:
            if result == "exists":
                flash(f"User '{username}' already exists.", "warning")
            else:
                flash(f"Error creating user: {result}", "danger")

    return render_template('register_public.html', stepca_online=stepca_online, ldap_online=ldap_online)


@auth_bp.route('/delete/<username>', methods=['POST'])
def delete_user(username):
    if 'username' not in session or not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for('auth.login'))

    if username == "admin":
        flash("Primary admin cannot be deleted!", "warning")
        return redirect(url_for('auth.user_management'))

    # Delete from LDAP first
    success, result = ldap_delete_user(username)
    if success:
        # Delete from DB
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            
            db.session.add(SystemAuditLog(
                user_id=session['user_id'],
                action_type="user_deleted",
                ip_address=request.remote_addr
                ))
            db.session.commit()

        flash(f"User '{username}' deleted successfully!", "success")
    else:
        flash(f"Error deleting user: {result}", "danger")

    return redirect(url_for('auth.user_management'))


@auth_bp.route('/admin/users', methods=['GET'])
def user_management():
    if 'username' not in session or not session.get('is_admin'):
        flash("Admin access required", "danger")
        return redirect(url_for('auth.login'))

    ldap_users = ldap_get_all_users()  # Returns username, full_name, email
    db_users = {u.username: u for u in User.query.all()}

    merged_users = []
    for u in ldap_users:
        username = u['username']
        merged_users.append({
            'username': username,
            'full_name': u['full_name'],
            'email': u['email'],  # Always from LDAP
            'is_admin': db_users.get(username).is_admin if username in db_users else False,
            'role': db_users.get(username).role if username in db_users else 'user'
        })

    return render_template('admin/user_management.html', users=merged_users)


@auth_bp.route('/logout')
def logout():
    if 'user_id' in session:
        db.session.add(SystemAuditLog(
            user_id=session['user_id'],
            action_type="logout",
            ip_address=request.remote_addr
        ))
        db.session.commit()

    session.clear()
    flash("Logged out successfully", "info")
    return redirect(url_for('main.home'))
