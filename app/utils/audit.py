from app import db
from app.models import CertificateAction
from datetime import datetime
from flask import session

def log_action(action_type, target_type=None, target_name=None, certificate_id=None, action_reason=None):
    """
    Logs any user/admin action.
    """
    user_id = session.get("user_id")  # Make sure you store user_id in session
    log = CertificateAction(
        user_id=user_id,
        certificate_id=certificate_id,
        action_type=action_type,
        target_type=target_type,
        target_name=target_name,
        action_reason=action_reason,
        action_timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()
