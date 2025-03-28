from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization


with open("server.key", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=b"password_17",
)

# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, "UA"),
    # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Slov`yansk"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Robot_dreams"),
    x509.NameAttribute(NameOID.COMMON_NAME, "www.robotdreams.cc"),
    x509.NameAttribute(NameOID.EMAIL_ADDRESS, "oleg.zasymenko@gmail.com"),
])).add_extension(
    x509.SubjectAlternativeName([
        # Describe what sites we want this certificate for.
        x509.DNSName("robotdreams.cc"),
        x509.DNSName("www.robotdreams.cc"),
        x509.DNSName("subdomain.robotdreams.cc"),
    ]),
    critical=False,
# Sign the CSR with our private key.
).sign(private_key, hashes.SHA256())
# Write our CSR out to disk.
with open("./server.csr", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# openssl req -text -noout -in server.csr