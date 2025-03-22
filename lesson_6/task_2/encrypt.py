from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes,serialization


message = b"Glory to Ukraine!"

with open("task_pub.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
    )
        
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(ciphertext.hex())

with open("task-2-message.txt", "w") as f:
    f.write(ciphertext.hex())
