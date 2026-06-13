import os
import tempfile
import subprocess
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file, current_app
from app import db
from app.models import User, Certificate, CertificateAction
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from flask import send_from_directory



cert_bp = Blueprint("certificates", __name__, url_prefix="/certificates")

# Use app.config for certificate folder
CERT_DIR = os.path.join(os.path.dirname(__file__), "../cert")
os.makedirs(CERT_DIR, exist_ok=True)

ACME_CHALLENGE_DIR = os.path.join(CERT_DIR, "acme-challenges")
os.makedirs(ACME_CHALLENGE_DIR, exist_ok=True)

@cert_bp.route("/.well-known/acme-challenge/<token>")
def acme_challenge(token):
    file_path = os.path.join(ACME_CHALLENGE_DIR, token)
    if os.path.exists(file_path):
        return send_from_directory(ACME_CHALLENGE_DIR, token)
    return "Not Found", 404

def issue_certificate_acme(common_name: str):
    """
    Issue certificate using ACME provisioner.
    """
    cert_path = os.path.join(CERT_DIR, f"{common_name}.crt")
    key_path = os.path.join(CERT_DIR, f"{common_name}.key")

    try:
        subprocess.check_output([
            "step", "ca", "certificate", common_name,
            cert_path, key_path,
            "--provisioner", "acme",
            "--ca-url", current_app.config["CA_URL"],
            "--root", os.path.join(CERT_DIR, "root_ca.crt"),
            "--force"
        ])
        return cert_path, key_path
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode() if hasattr(e, "stderr") else str(e)
        raise RuntimeError(f"ACME issuance failed: {stderr}")



# ------------------ HELPER FUNCTION TO ISSUE CERTIFICATE ------------------
def issue_certificate(common_name: str):
    """
    Issues certificate using Step-CA admin credentials
    Password file stored inside application directory (Windows-safe)
    """

    cert_path = os.path.join(CERT_DIR, f"{common_name}.crt")
    key_path = os.path.join(CERT_DIR, f"{common_name}.key")

    CA_URL = current_app.config.get("CA_URL")
    PROVISIONER_EMAIL = current_app.config.get("PROVISIONER_EMAIL")
    PROVISIONER_PASSWORD = current_app.config.get("PROVISIONER_PASSWORD")

    if not PROVISIONER_PASSWORD:
        raise ValueError("PROVISIONER_PASSWORD is not set")

    ROOT_CERT_PATH = os.path.join(CERT_DIR, "root_ca.crt")

    # Password file inside project cert directory
    pwfile = os.path.join(CERT_DIR, ".step_pw")

    # Write password
    with open(pwfile, "w", encoding="utf-8") as f:
        f.write(PROVISIONER_PASSWORD)

    try:
        # Generate token
        token = subprocess.check_output(
            [
                "step", "ca", "token", common_name,
                "--provisioner", PROVISIONER_EMAIL,
                "--password-file", pwfile,
                "--ca-url", CA_URL,
                "--root", ROOT_CERT_PATH
            ],
            text=True
        ).strip()

        # Issue certificate
        subprocess.check_output(
            [
                "step", "ca", "certificate", common_name,
                cert_path, key_path,
                "--token", token,
                "--ca-url", CA_URL,
                "--root", ROOT_CERT_PATH,
                "--force"
            ],
            text=True
        )

        return cert_path, key_path

    finally:
        # Cleanup
        try:
            os.remove(pwfile)
        except Exception:
            pass


def inspect_certificate(cert_path):
    """
    Reads a certificate (.crt/.pem) and returns a dictionary with details.
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
            "serial_number": cert.serial_number,
            "not_before": cert.not_valid_before,
            "not_after": cert.not_valid_after,
            "signature_algorithm": cert.signature_hash_algorithm.name,
            "public_key": pubkey_str[:500] + "..."  # truncated for display
        }
    except Exception as e:
        print(f"Error inspecting certificate: {e}")
        return None

@cert_bp.route("/admin/acme_issue/<int:cert_id>", methods=["POST"])
def acme_issue_certificate(cert_id):
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    cert = Certificate.query.get_or_404(cert_id)
    try:
        cert_path, key_path = issue_certificate_acme(cert.common_name)
        cert.certificate_file = cert_path
        cert.key_file = key_path
        cert.status = "Issued"
        cert.issued_at = datetime.utcnow()
        cert.generated_by_admin = True
        cert.admin_action_by = session["username"]

        # Inspect certificate for expiry
        details = inspect_certificate(cert_path)
        if details:
            cert.expiry_date = details["not_after"]

        # Log action
        action = CertificateAction(
            certificate_id=cert.id,
            user_id=cert.user_id,
            action_type="acme_issued",
            action_timestamp=datetime.utcnow()
        )
        db.session.add(action)
        db.session.commit()

        flash(f"ACME certificate issued for {cert.common_name}", "success")
    except Exception as e:
        flash(f"Error issuing ACME certificate: {e}", "danger")

    return redirect(url_for("certificates.admin_all_certs"))

@cert_bp.route("/admin/renew/<int:cert_id>", methods=["POST"])
def renew_certificate(cert_id):
    # auth check (same pattern you use elsewhere)
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    cert = Certificate.query.get_or_404(cert_id)

    # Use same issuing helper as generate route to re-issue (it uses --force)
    try:
        # issue_certificate returns (cert_path, key_path) and uses app config (current_app)
        new_cert_path, new_key_path = issue_certificate(cert.common_name)

        # Save file paths in DB. Use basename so UI shows friendly filename if you prefer.
        # Update whichever fields exist on your model.
        cert.certificate_file = new_cert_path  # existing column in your model
        # if your model has a key file column (maybe named key_file or private_key_file), update it:
        if hasattr(cert, "key_file"):
            cert.key_file = new_key_path
        elif hasattr(cert, "private_key_file"):
            cert.private_key_file = new_key_path
        # else: we don't create unknown attributes (DB model doesn't have column)

        from datetime import datetime, timedelta

        cert.status = "Issued"  # or "Renewed"
        cert.issued_at = datetime.utcnow()
        cert.expiry_date = datetime.utcnow() + timedelta(days=365)  # Set new expiry date
        cert.updated_at = datetime.utcnow()
        db.session.add(cert)
        db.session.commit()


        # Log admin action
        # find current user id if stored in DB (session stores username)
        admin_user = None
        if session.get("username"):
            admin_user = User.query.filter_by(username=session.get("username")).first()
        action = CertificateAction(
            certificate_id=cert.id,
            user_id=admin_user.id if admin_user else None,
            action_type="renewed",
            action_timestamp=datetime.utcnow()
        )
        db.session.add(action)
        db.session.commit()

        flash(f"Certificate for {cert.common_name} renewed (re-issued) successfully!", "success")
    except subprocess.CalledProcessError as e:
        # subprocess errors from issue_certificate (step CLI)
        stderr = e.stderr.decode() if hasattr(e, "stderr") and e.stderr else str(e)
        flash(f"Step-CA error during renewal: {stderr}", "danger")
    except Exception as e:
        flash(f"Error renewing certificate: {e}", "danger")

    return redirect(url_for("certificates.admin_all_certs"))
    
# ------------------ ROUTES ------------------
# User CSR submission
@cert_bp.route("/submit_csr", methods=["GET", "POST"])
def submit_csr():
    if "username" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(username=session["username"]).first()
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        csr_content = request.form.get("csr_content")
        common_name = request.form.get("common_name")

        if not csr_content or not common_name:
            flash("CSR and Common Name are required!", "danger")
        else:
            cert = Certificate(
                user_id=user.id,
                common_name=common_name,
                csr_file=os.path.join(CERT_DIR, f"{common_name}.csr"),
                status="Pending",
            )
            with open(cert.csr_file, "w") as f:
                f.write(csr_content)

            db.session.add(cert)
            db.session.commit()
            flash("CSR submitted successfully!", "success")
            return redirect(url_for("certificates.user_certificates"))

    return render_template("user/submit_csr.html")


# User view their certificates
@cert_bp.route("/my_certificates")
def user_certificates():
    if "username" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("auth.login"))

    user = User.query.filter_by(username=session["username"]).first()
    certificates = Certificate.query.filter_by(user_id=user.id).order_by(Certificate.created_at.desc()).all()
    return render_template("user/my_certificates.html", certificates=certificates)


# Admin view CSR requests
@cert_bp.route("/admin/csr_requests")
def admin_csr_requests():
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    # Fetch all pending CSRs
    csrs = Certificate.query.filter_by(status="Pending").all()

    # Read CSR content for each certificate
    csr_contents = {}
    for csr in csrs:
        if csr.csr_file and os.path.exists(csr.csr_file):
            with open(csr.csr_file, "r") as f:
                csr_contents[csr.id] = f.read()
        else:
            csr_contents[csr.id] = "CSR file not found."

    return render_template("admin/csr_requests.html", csrs=csrs, csr_contents=csr_contents)


@cert_bp.route("/admin/approve/<int:cert_id>", methods=["GET", "POST"])
def approve_csr(cert_id):
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    cert = Certificate.query.get_or_404(cert_id)
    try:
        # Issue the certificate
        cert_path, key_path = issue_certificate(cert.common_name)
        cert.certificate_file = cert_path
        cert.key_file = key_path
        cert.status = "Issued"
        cert.issued_at = datetime.utcnow()
        cert.generated_by_admin = True
        cert.admin_action_by = session["username"]

        # Inspect the certificate to get validity dates
        cert_details = inspect_certificate(cert_path)
        if cert_details:
            cert.expiry_date = cert_details.get("not_after")

        # Log action
        action = CertificateAction(
            certificate_id=cert.id,
            user_id=cert.user_id,
            action_type="approved",
        )
        db.session.add(action)
        db.session.commit()

        flash(f"CSR for {cert.common_name} approved and certificate issued!", "success")
    except subprocess.CalledProcessError as e:
        flash(f"Error issuing certificate: {e}", "danger")
    except Exception as e:
        flash(f"Unexpected error: {e}", "danger")

    return redirect(url_for("certificates.admin_all_certs"))


@cert_bp.route("/view/<int:cert_id>")
def view_certificate(cert_id):
    cert = Certificate.query.get_or_404(cert_id)
    cert_details = inspect_certificate(cert.certificate_file)

    if not cert_details:
        flash("Certificate file not found or invalid", "danger")
        if session.get("is_admin"):
            return redirect(url_for("certificates.admin_all_certs"))
        else:
            return redirect(url_for("certificates.user_certificates"))

    return render_template("view_certificate.html", cert=cert, cert_details=cert_details)



# Admin reject CSR
@cert_bp.route("/admin/reject/<int:cert_id>", methods=["POST"])
def reject_csr(cert_id):
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    cert = Certificate.query.get_or_404(cert_id)
    reason = request.form.get("reason", "No reason provided")
    cert.status = "Rejected"
    cert.rejection_reason = reason
    cert.admin_action_by = session["username"]

    action = CertificateAction(
        certificate_id=cert.id,
        user_id=session.get("user_id"),
        action_type="rejected",
        action_reason=reason
    )
    db.session.add(action)
    db.session.commit()
    flash(f"CSR for {cert.common_name} rejected!", "warning")
    return redirect(url_for("certificates.admin_all_certs"))

# Admin direct certificate generation
@cert_bp.route("/admin/generate", methods=["GET", "POST"])
def admin_generate_cert():
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        common_name = request.form.get("common_name")
        if not common_name:
            flash("Common Name is required!", "danger")
            return redirect(url_for("certificates.admin_generate_cert"))

        try:
            # Issue certificate using Step-CA
            cert_path, key_path = issue_certificate(common_name)

            # Save certificate record
            cert = Certificate(
                user_id=None,
                common_name=common_name,
                certificate_file=cert_path,
                status="Generated",
                generated_by_admin=True,
                issued_at=datetime.utcnow()
            )
            db.session.add(cert)
            db.session.commit()

            # Log admin action separately
            action = CertificateAction(
                certificate_id=cert.id,
                user_id=session.get("user_id"),  # Admin performing the action
                action_type="generated"
            )
            db.session.add(action)
            db.session.commit()

            flash(f"Certificate for {common_name} generated successfully!", "success")
            return redirect(url_for("certificates.admin_all_certs"))
        except subprocess.CalledProcessError as e:
            flash(f"Error generating certificate: {e}", "danger")

    return render_template("admin/generate_cert.html")

# -------------------------------
# Download only the certificate (.crt)
# -------------------------------
@cert_bp.route("/download_crt/<int:cert_id>")
def download_crt(cert_id):
    if "username" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("auth.login"))

    cert = Certificate.query.get_or_404(cert_id)
    user = User.query.filter_by(username=session["username"]).first()

    # Access control
    if not session.get("is_admin") and cert.user_id != user.id:
        flash("You do not have permission to download this certificate", "danger")
        return redirect(url_for("certificates.user_certificates"))

    if not cert.certificate_file or not os.path.exists(cert.certificate_file):
        flash("Certificate file not found!", "danger")
        return redirect(url_for("certificates.user_certificates"))

    # Log action
    action = CertificateAction(
        certificate_id=cert.id,
        user_id=user.id,
        action_type="downloaded_crt"
    )
    db.session.add(action)
    db.session.commit()

    return send_file(cert.certificate_file, as_attachment=True, download_name=f"{cert.common_name}.crt")


# -------------------------------
# Download only the private key (.key)
# -------------------------------
@cert_bp.route("/download_key/<int:cert_id>")
def download_key(cert_id):
    if "username" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("auth.login"))

    cert = Certificate.query.get_or_404(cert_id)
    user = User.query.filter_by(username=session["username"]).first()

    # Access control
    if not session.get("is_admin") and cert.user_id != user.id:
        flash("You do not have permission to download this private key", "danger")
        return redirect(url_for("certificates.user_certificates"))

    # Derive key path based on certificate path
    key_path = cert.certificate_file.replace(".crt", ".key")

    if not os.path.exists(key_path):
        flash("Private key file not found!", "danger")
        return redirect(url_for("certificates.user_certificates"))

    # Log action
    action = CertificateAction(
        certificate_id=cert.id,
        user_id=user.id,
        action_type="downloaded_key"
    )
    db.session.add(action)
    db.session.commit()

    return send_file(key_path, as_attachment=True, download_name=f"{cert.common_name}.key")

@cert_bp.route("/download_root_ca")
def download_root_ca():
    """
    Allows users and admins to download the Root CA certificate.
    """
    if "username" not in session:
        flash("Please login first", "warning")
        return redirect(url_for("auth.login"))

    root_ca_path = os.path.join(CERT_DIR, "root_ca.crt")

    if not os.path.exists(root_ca_path):
        flash("Root CA certificate not found on server!", "danger")
        return redirect(request.referrer or url_for("dashboard.user_dashboard"))

    return send_file(
        root_ca_path,
        as_attachment=True,
        download_name="root_ca.crt",
        mimetype="application/x-x509-ca-cert"
    )

# Admin revoke certificate
@cert_bp.route("/admin/revoke/<int:cert_id>", methods=["POST"])
def revoke_certificate(cert_id):
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    cert = Certificate.query.get_or_404(cert_id)
    cert.status = "Revoked"
    cert.revoked_at = datetime.utcnow()
    db.session.add(cert)
    db.session.commit()

    flash(f"Certificate for {cert.common_name} revoked successfully!", "success")
    return redirect(url_for("certificates.admin_all_certs"))


# Admin view all certificates
@cert_bp.route("/admin/all")
def admin_all_certs():
    if "username" not in session or not session.get("is_admin"):
        flash("Admin access required", "danger")
        return redirect(url_for("auth.login"))

    # Fetch all certificates
    certs = Certificate.query.order_by(Certificate.created_at.desc()).all()

    # Fetch pending CSRs
    csrs = Certificate.query.filter_by(status="Pending").all()

    # Read CSR content
    csr_contents = {}
    for csr in csrs:
        if csr.csr_file and os.path.exists(csr.csr_file):
            with open(csr.csr_file, "r") as f:
                csr_contents[csr.id] = f.read()
        else:
            csr_contents[csr.id] = "CSR file not found."

    # Ensure the session fetches fresh data
    db.session.expire_all()
    from datetime import datetime
    return render_template(
        "admin/all_certs.html",
        certificates=certs,
        csrs=csrs,
        csr_contents=csr_contents,
        now=datetime.utcnow()
    )
