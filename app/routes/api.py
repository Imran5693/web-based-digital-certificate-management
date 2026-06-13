from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from app import db
from app.models.certificate import Certificate
from app.models.user import User
from app.utils.stepca_utils import issue_certificate, check_stepca_status
from app.utils.validators import validate_common_name
import logging

api_bp = Blueprint('api', __name__)
logger = logging.getLogger(__name__)

@api_bp.route('/certificates', methods=['GET'])
@login_required
def list_certificates():
    """API endpoint to list certificates (supports ACME clients)"""
    try:
        if current_user.is_admin:
            certificates = Certificate.query.all()
        else:
            certificates = Certificate.query.filter_by(user_id=current_user.id).all()
        
        result = []
        for cert in certificates:
            result.append({
                'id': cert.id,
                'common_name': cert.common_name,
                'status': cert.status,
                'issued_at': cert.issued_at.isoformat() if cert.issued_at else None,
                'expires_at': cert.expires_at.isoformat() if cert.expires_at else None,
                'created_at': cert.created_at.isoformat()
            })
        
        return jsonify({'certificates': result})
    
    except Exception as e:
        logger.error(f"API Error in list_certificates: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    stepca_online = check_stepca_status()
    
    return jsonify({
        'status': 'healthy' if stepca_online else 'degraded',
        'stepca_online': stepca_online,
        'timestamp': datetime.utcnow().isoformat()
    })

@api_bp.route('/certificate/<int:cert_id>', methods=['GET'])
@login_required
def get_certificate(cert_id):
    """Get specific certificate details"""
    try:
        cert = Certificate.query.get_or_404(cert_id)
        
        # Authorization check
        if not current_user.is_admin and cert.user_id != current_user.id:
            return jsonify({'error': 'Access denied'}), 403
        
        return jsonify({
            'certificate': {
                'id': cert.id,
                'common_name': cert.common_name,
                'status': cert.status,
                'issued_at': cert.issued_at.isoformat() if cert.issued_at else None,
                'expires_at': cert.expires_at.isoformat() if cert.expires_at else None,
                'created_at': cert.created_at.isoformat()
            }
        })
    
    except Exception as e:
        logger.error(f"API Error in get_certificate: {e}")
        return jsonify({'error': 'Internal server error'}), 500