import os
import requests
import json
import urllib3
from flask import current_app
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

def check_stepca_status():
    """Return True if Step-CA server is reachable and online, False otherwise."""
    try:
        ca_url = current_app.config.get('CA_URL') or os.getenv("CA_URL")
        resp = requests.get(f"{ca_url}/health", verify=False, timeout=3)
        if resp.status_code == 200:
            return True
    except requests.exceptions.RequestException:
        pass
    return False

def generate_certificate(common_name):
    """
    Generate a certificate from Step-CA via API
    """
    try:
        ca_url = current_app.config.get('CA_URL') or os.getenv("CA_URL")
        provisioner_email = current_app.config.get('PROVISIONER_EMAIL') or os.getenv("PROVISIONER_EMAIL")
        provisioner_password = current_app.config.get('PROVISIONER_PASSWORD') or os.getenv("PROVISIONER_PASSWORD")
        
        payload = {
            "name": common_name,
            "provisioner": provisioner_email,
            "password": provisioner_password
        }
        url = f"{ca_url}/api/certificate"
        response = requests.post(url, json=payload, verify=False)
        if response.status_code == 200:
            return True, response.json()
        else:
            return False, f"Error: {response.text}"
    except Exception as e:
        return False, str(e)

def list_certificates():
    """
    Retrieve list of certificates (mocked, since Step-CA doesn't expose all easily).
    In production, integrate with CA database or stored certificate index.
    """
    try:
        ca_url = current_app.config.get('CA_URL') or os.getenv("CA_URL")
        url = f"{ca_url}/api/certificates"
        response = requests.get(url, verify=False)
        if response.status_code == 200:
            return response.json()
        else:
            return []
    except Exception as e:
        logger.error(f"Error fetching certificates: {e}")
        return []

def revoke_certificate(cert_id, reason="keyCompromise"):
    """
    Revoke a certificate by ID using Step-CA API
    """
    try:
        ca_url = current_app.config.get('CA_URL') or os.getenv("CA_URL")
        payload = {"reason": reason}
        url = f"{ca_url}/api/certificate/{cert_id}/revoke"
        response = requests.post(url, json=payload, verify=False)
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Error revoking certificate: {e}")
        return False

# 🎯 CORRECTED - Using your existing certificate folder structure
def issue_certificate(common_name):
    """
    Your certificates.py uses this function! 
    This wraps your existing generate_certificate function with proper paths
    """
    try:
        # Use your existing CERT_DIR from certificates.py
        CERT_DIR = os.path.join(os.path.dirname(__file__), "../cert")
        os.makedirs(CERT_DIR, exist_ok=True)
        
        cert_path = os.path.join(CERT_DIR, f"{common_name}.crt")
        key_path = os.path.join(CERT_DIR, f"{common_name}.key")
        
        # Check if certificate already exists
        if os.path.exists(cert_path) and os.path.exists(key_path):
            logger.info(f"Certificate already exists for {common_name}")
            return cert_path, key_path
            
        # Generate new certificate using your Step-CA API
        success, result = generate_certificate(common_name)
        if success:
            # Save certificate and key to files (adjust based on your API response format)
            if isinstance(result, dict):
                # If API returns certificate data in response
                cert_data = result.get('certificate', '')
                key_data = result.get('private_key', '')
                
                if cert_data and key_data:
                    with open(cert_path, 'w') as f:
                        f.write(cert_data)
                    with open(key_path, 'w') as f:
                        f.write(key_data)
                    logger.info(f"Certificate generated for {common_name}")
                    return cert_path, key_path
            else:
                # If you need to use step CLI (like in your original certificates.py)
                import tempfile
                import subprocess
                
                # Your existing step CLI implementation from certificates.py
                CA_URL = current_app.config.get("CA_URL")
                PROVISIONER_EMAIL = current_app.config.get("PROVISIONER_EMAIL")
                PROVISIONER_PASSWORD = current_app.config.get("PROVISIONER_PASSWORD")
                ROOT_CERT_PATH = os.path.join(CERT_DIR, "root_ca.crt")

                # Write password to temp file
                with tempfile.NamedTemporaryFile("w", delete=False) as f:
                    f.write(PROVISIONER_PASSWORD)
                    pwfile = f.name

                try:
                    # Generate token
                    token = subprocess.check_output([
                        "step", "ca", "token", common_name,
                        "--provisioner", PROVISIONER_EMAIL,
                        "--password-file", pwfile,
                        "--ca-url", CA_URL,
                        "--root", ROOT_CERT_PATH
                    ]).decode().strip()

                    # Issue certificate using step CLI (your existing method)
                    subprocess.check_output([
                        "step", "ca", "certificate", common_name,
                        cert_path, key_path,
                        "--token", token,
                        "--ca-url", CA_URL,
                        "--root", ROOT_CERT_PATH,
                        "--force"
                    ])
                    return cert_path, key_path
                finally:
                    try:
                        os.remove(pwfile)
                    except FileNotFoundError:
                        pass
        
        raise Exception(f"Certificate generation failed: {result}")
        
    except Exception as e:
        logger.error(f"Error in issue_certificate for {common_name}: {e}")
        raise Exception(f"Certificate generation failed: {str(e)}")

# 🎯 CORRECTED - Real certificate inspection using cryptography library
def inspect_certificate(cert_path):
    """
    Real certificate inspection using cryptography library
    """
    if not cert_path or not os.path.exists(cert_path):
        return None

    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Get public key in a readable form
        pubkey = cert.public_key()
        if hasattr(pubkey, "public_bytes"):  # For RSA or EC keys
            pubkey_str = pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        else:
            pubkey_str = str(pubkey)

        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial_number": str(cert.serial_number),
            "not_before": cert.not_valid_before,
            "not_after": cert.not_valid_after,
            "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown",
            "public_key": pubkey_str[:500] + "..." if len(pubkey_str) > 500 else pubkey_str
        }
    except Exception as e:
        logger.error(f"Error inspecting certificate {cert_path}: {e}")
        return None