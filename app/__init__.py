import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler
from app.config import Config


# Create db object globally
db = SQLAlchemy()


def create_app():
    load_dotenv()

    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)

    app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_key")
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URI", "sqlite:///wca.db")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize db with app
    db.init_app(app)

    # Import models so tables can be created
    from app.models import User, Certificate

    # Import and register blueprints
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.certificates import cert_bp, issue_certificate_acme, inspect_certificate

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(cert_bp)

    # Create tables if they don't exist
    with app.app_context():
        db.create_all()
        # Import audit_listener at the end to avoid circular imports
        from app.utils import audit_listener
        start_scheduler(app)  # start ACME auto-renew scheduler

    return app


# --------------------- Scheduler & Auto-renew --------------------- #
def auto_renew_certificates(app):
    from app.models import Certificate  # import inside function to avoid circular imports
    from app.routes.certificates import issue_certificate_acme, inspect_certificate

    with app.app_context():
        for cert in Certificate.query.filter(Certificate.status == "Issued").all():
            if cert.expiry_date and (cert.expiry_date - datetime.utcnow() < timedelta(days=30)):
                try:
                    cert_path, key_path = issue_certificate_acme(cert.common_name)
                    cert.certificate_file = cert_path
                    cert.key_file = key_path
                    cert.issued_at = datetime.utcnow()

                    details = inspect_certificate(cert_path)
                    if details:
                        cert.expiry_date = details.get("not_after")

                    db.session.commit()
                    print(f"[ACME Renewal] Certificate renewed: {cert.common_name}")
                except Exception as e:
                    print(f"[ACME Renewal] Failed for {cert.common_name}: {e}")


def start_scheduler(app):
    scheduler = BackgroundScheduler()
    scheduler.add_job(lambda: auto_renew_certificates(app), 'interval', hours=24)
    scheduler.start()
    print("[Scheduler] ACME auto-renew scheduler started")
