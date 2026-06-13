from flask import Blueprint, render_template 
from app.utils.stepca_utils import check_stepca_status
from app.utils.ldap_utils import check_ldap_status

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def home():
    # Check Step-CA and LDAP status
    stepca_online = check_stepca_status()  # returns True/False
    ldap_online = check_ldap_status()      # returns True/False
    return render_template(
        'home.html',
        stepca_online=stepca_online,
        ldap_online=ldap_online
    )
  
