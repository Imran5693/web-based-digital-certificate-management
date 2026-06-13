# update_expiry.py
from datetime import datetime
from app import create_app, db
from app.models import Certificate
from app.routes.certificates import inspect_certificate

app = create_app()
app.app_context().push()

certs = Certificate.query.filter(Certificate.status == 'Issued').all()

for cert in certs:
    if cert.certificate_file:
        details = inspect_certificate(cert.certificate_file)
        if details:
            # details is a dict
            cert.expiry_date = details.get("not_after")  # use .get()
            print(f"Updated expiry for {cert.common_name}: {cert.expiry_date}")
        else:
            print(f"Certificate file not found or invalid: {cert.common_name}")

db.session.commit()
print("✅ All expiry dates updated successfully.")
