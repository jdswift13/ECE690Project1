from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
#code based on https://cryptography.io/en/latest/x509/tutorial.html
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

with open("ca_key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"temp"),
    ))
    subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"KS"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Manhattan"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"K-State"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"ksu.edu"),
])
    cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=10)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
).sign(key, hashes.SHA256())
    with open("ca_key.crt", "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(cert)

key1 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
with open("user_key.pem", "wb") as f:
    f.write(key1.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"temp"),
    ))
    subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"KS"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Manhattan"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"K-State"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"ksu.edu"),
])
    cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key1.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=10)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
).sign(key, hashes.SHA256())
    with open("user_key.crt", "wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(cert)
  