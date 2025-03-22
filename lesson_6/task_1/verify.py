from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.exceptions import InvalidSignature


# Key generation

# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
# )
# public_key = private_key.public_key()


# # Key serialization

# private_key_pem = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.BestAvailableEncryption(b"secret"),
# )

# public_key_pem = public_key.public_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PublicFormat.SubjectPublicKeyInfo,
# )

# with open("priv.pem", "wb") as f:
#     f.write(private_key_pem)

# with open("pub.pem", "wb") as f:
#     f.write(public_key_pem)

def verify():

    with open("priv.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b"secret",
    )

    with open("task_message.txt", "r") as msg_file:
        message = bytes.fromhex(msg_file.read())

    signature = private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

    public_key = private_key.public_key()

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("The signature was verified successfully")
    except InvalidSignature:
        print("The signature verification failed")


verify()
# The signature was verified successfully 