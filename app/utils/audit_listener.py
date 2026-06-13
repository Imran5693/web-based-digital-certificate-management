from sqlalchemy import event
from datetime import datetime
from app import db
from app.models import Certificate, CertificateAction
from flask import session

def get_current_user_id():
    """Get current logged-in user ID from session, may be None."""
    return session.get("user_id")

# -------------------- Certificate Actions --------------------
@event.listens_for(Certificate, 'after_insert')
def certificate_insert(mapper, connection, target):
    """Log certificate creation/issuance automatically."""
    connection.execute(
        CertificateAction.__table__.insert(),
        {
            'user_id': get_current_user_id(),
            'certificate_id': target.id,
            'action_type': 'created' if target.generated_by_admin else 'issued',
            'action_timestamp': datetime.utcnow()
        }
    )

@event.listens_for(Certificate, 'after_update')
def certificate_update(mapper, connection, target):
    """Log certificate updates such as revoked, renewed, rejected."""
    action_type = None
    if target.status == 'Revoked':
        action_type = 'revoked'
    elif target.status == 'Issued':
        action_type = 'renewed'
    elif target.status == 'Rejected':
        action_type = 'rejected'

    if action_type:
        connection.execute(
            CertificateAction.__table__.insert(),
            {
                'user_id': get_current_user_id(),
                'certificate_id': target.id,
                'action_type': action_type,
                'action_timestamp': datetime.utcnow()
            }
        )
