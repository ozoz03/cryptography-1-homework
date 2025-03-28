import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

with open("server.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b"password_17",
)

# Various details about who we are. For a self-signed certificate the
# subject and issuer are always the same.
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
    # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Slov`yansk"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Robot_dreams"),
    x509.NameAttribute(NameOID.COMMON_NAME, "www.robotdreams.cc"),
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "oleg.zasymenko@gmail.com"),
])
cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    # Our certificate will be valid for 10 days
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
    critical=False,
# Sign our certificate with our private key
).sign(private_key, hashes.SHA256())
# Write our certificate out to disk.
with open("./server.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

# openssl x509 -text -noout -in server.crt
# openssl asn1parse -in server.crt 