import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "default_secret")
    LDAP_URI = os.getenv("LDAP_URI")
    LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")
    LDAP_ADMIN_DN = os.getenv("LDAP_ADMIN_DN")
    LDAP_ADMIN_PASSWORD = os.getenv("LDAP_ADMIN_PASSWORD")

    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # 30 min idle timeout
    SESSION_PERMANENT = True

    CA_URL = os.getenv("CA_URL")
    CA_FINGERPRINT = os.getenv("CA_FINGERPRINT")
    PROVISIONER_EMAIL = os.getenv("PROVISIONER_EMAIL")
    PROVISIONER_PASSWORD = os.getenv("PROVISIONER_PASSWORD")

    CA_SSH_HOST = os.getenv("CA_SSH_HOST")
    CA_SSH_USER = os.getenv("CA_SSH_USER")
    CA_SSH_PASSWORD = os.getenv("CA_SSH_PASSWORD")
