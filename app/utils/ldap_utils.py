from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_DELETE, core, SUBTREE
import os
from flask import current_app
import logging

logger = logging.getLogger(__name__)

def check_ldap_status():
    """Return True if LDAP server is reachable and admin can bind, False otherwise."""
    try:
        ldap_uri = current_app.config.get('LDAP_URI') or os.getenv("LDAP_URI")
        ldap_admin_dn = current_app.config.get('LDAP_ADMIN_DN') or os.getenv("LDAP_ADMIN_DN")
        ldap_admin_password = current_app.config.get('LDAP_ADMIN_PASSWORD') or os.getenv("LDAP_ADMIN_PASSWORD")
        
        server = Server(ldap_uri, get_info=ALL)
        conn = Connection(server, user=ldap_admin_dn, password=ldap_admin_password, auto_bind=True)
        return conn.bound
    except Exception as e:
        logger.error(f"LDAP status check failed: {e}")
        return False

def _get_admin_connection():
    """Return an admin connection to LDAP."""
    ldap_uri = current_app.config.get('LDAP_URI') or os.getenv("LDAP_URI")
    ldap_admin_dn = current_app.config.get('LDAP_ADMIN_DN') or os.getenv("LDAP_ADMIN_DN")
    ldap_admin_password = current_app.config.get('LDAP_ADMIN_PASSWORD') or os.getenv("LDAP_ADMIN_PASSWORD")
    
    server = Server(ldap_uri, get_info=ALL)
    conn = Connection(server, user=ldap_admin_dn, password=ldap_admin_password, auto_bind=True)
    return conn

def ldap_authenticate_user(username, password):
    """
    Authenticate user against LDAP.
    Returns: (success: bool, message: str, is_admin: bool)
    """
    ldap_uri = current_app.config.get('LDAP_URI') or os.getenv("LDAP_URI")
    ldap_base_dn = current_app.config.get('LDAP_BASE_DN') or os.getenv("LDAP_BASE_DN")
    
    server = Server(ldap_uri, get_info=ALL)
    user_dn = f"uid={username},ou=users,{ldap_base_dn}"

    try:
        conn = Connection(server, user=user_dn, password=password)
        if conn.bind():
            # Check if user is admin by checking group membership
            admin_conn = _get_admin_connection()
            admin_conn.search(
                f"ou=groups,{ldap_base_dn}",
                f"(&(cn=CAAdmins)(member={user_dn}))",
                search_scope=SUBTREE,
                attributes=['cn']
            )
            is_admin = bool(admin_conn.entries)
            return True, "Login successful", is_admin
        else:
            # Check if user exists
            admin_conn = _get_admin_connection()
            admin_conn.search(
                f"ou=users,{ldap_base_dn}", 
                f"(uid={username})", 
                attributes=["uid"]
            )
            if not admin_conn.entries:
                return False, "User not found in LDAP", False
            else:
                return False, "Incorrect password", False
    except core.exceptions.LDAPException as e:
        logger.error(f"LDAP authentication error for {username}: {e}")
        return False, f"LDAP Error: {str(e)}", False

def ldap_get_all_users():
    """Return list of all LDAP users with details."""
    ldap_base_dn = current_app.config.get('LDAP_BASE_DN') or os.getenv("LDAP_BASE_DN")
    
    try:
        conn = _get_admin_connection()
        conn.search(
            f"ou=users,{ldap_base_dn}", 
            "(uid=*)", 
            attributes=["uid", "cn", "mail"]
        )
        
        users = []
        for entry in conn.entries:
            users.append({
                'username': entry.uid.value,
                'full_name': entry.cn.value if hasattr(entry, 'cn') else entry.uid.value,
                'email': entry.mail.value if hasattr(entry, 'mail') else f"{entry.uid.value}@example.com"
            })
        return users
    except core.exceptions.LDAPException as e:
        logger.error(f"LDAP error getting users: {e}")
        return []

def _get_next_uid_number():
    """Find next UID number automatically."""
    ldap_base_dn = current_app.config.get('LDAP_BASE_DN') or os.getenv("LDAP_BASE_DN")
    
    conn = _get_admin_connection()
    conn.search(f"ou=users,{ldap_base_dn}", "(uid=*)", attributes=["uidNumber"])
    uids = []
    for entry in conn.entries:
        if hasattr(entry, "uidNumber"):
            uids.append(int(entry.uidNumber.value))
    return max(uids, default=1000) + 1

def ldap_create_user(username, password, full_name=None, role='user'):
    """
    Create a new user in LDAP and return success status.
    role: 'admin' or 'user'
    """
    ldap_base_dn = current_app.config.get('LDAP_BASE_DN') or os.getenv("LDAP_BASE_DN")
    users_ou = f"ou=users,{ldap_base_dn}"
    groups_ou = f"ou=groups,{ldap_base_dn}"
    ca_users_group_dn = f"cn=CAUsers,{groups_ou}"
    ca_admins_group_dn = f"cn=CAAdmins,{groups_ou}"
    
    conn = _get_admin_connection()
    user_dn = f"uid={username},{users_ou}"

    # Check if user already exists
    try:
        conn.search(users_ou, f"(uid={username})", attributes=["uid"])
        if conn.entries:
            logger.info(f"User {username} already exists in LDAP.")
            return False, "exists"
    except core.exceptions.LDAPException as e:
        logger.error(f"LDAP connection error: {e}")
        return False, "connection_error"

    # User does not exist → create
    uid_number = _get_next_uid_number()
    
    # Choose gid based on role
    if role == 'admin':
        gid_number = 1001  # CAAdmins
        group_dn = ca_admins_group_dn
    else:
        gid_number = 1002  # CAUsers
        group_dn = ca_users_group_dn

    attributes = {
        "objectClass": ["inetOrgPerson", "posixAccount", "top"],
        "cn": full_name or username,
        "sn": full_name.split(" ")[-1] if full_name and " " in full_name else full_name or username,
        "uid": username,
        "uidNumber": str(uid_number),
        "gidNumber": str(gid_number),
        "homeDirectory": f"/home/{username}",
        "loginShell": "/bin/bash",
        "mail": f"{username}@example.com",
        "userPassword": password,
    }

    try:
        if conn.add(user_dn, attributes=attributes):
            # Add user to appropriate group
            conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
            logger.info(f"User {username} created successfully in LDAP with role: {role}")
            return True, "success"
        else:
            logger.error(f"LDAP add failed: {conn.result}")
            return False, "add_failed"
    except core.exceptions.LDAPException as e:
        logger.error(f"LDAP error creating user {username}: {e}")
        return False, f"ldap_error: {str(e)}"

def ldap_delete_user(username):
    """Delete user and remove from CAUsers/CAAdmins groups."""
    ldap_base_dn = current_app.config.get('LDAP_BASE_DN') or os.getenv("LDAP_BASE_DN")
    users_ou = f"ou=users,{ldap_base_dn}"
    groups_ou = f"ou=groups,{ldap_base_dn}"
    ca_users_group_dn = f"cn=CAUsers,{groups_ou}"
    ca_admins_group_dn = f"cn=CAAdmins,{groups_ou}"
    
    conn = _get_admin_connection()
    user_dn = f"uid={username},{users_ou}"

    try:
        # Remove from CAUsers and CAAdmins groups
        conn.modify(ca_users_group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
        conn.modify(ca_admins_group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
        
        # Delete user DN
        conn.delete(user_dn)
        success = conn.result["description"] == "success"
        if success:
            logger.info(f"User {username} deleted successfully from LDAP")
        else:
            logger.error(f"LDAP delete failed: {conn.result}")
        return success, "success" if success else conn.result["description"]
    except core.exceptions.LDAPException as e:
        logger.error(f"LDAP Error deleting user {username}: {e}")
        return False, f"ldap_error: {str(e)}"

# 🆕 ADD THIS FUNCTION - Your auth.py expects ldap_connect()
def ldap_connect():
    """
    Connect to LDAP using admin credentials for user management.
    This function is referenced in your existing auth.py
    """
    return _get_admin_connection()

# 🆕 ADD THIS FUNCTION - Your auth.py uses this name
def is_admin(groups):
    """Check if user is admin or CA manager."""
    for g in groups:
        if 'admin' in g.lower() or 'ca_manager' in g.lower():
            return True
    return False