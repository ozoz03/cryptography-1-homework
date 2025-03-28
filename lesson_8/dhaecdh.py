from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii



# Відкритий ключ Alice для підпису (довгостроковий) у форматі PEM (алгоритм ECDSA з кривою SECP256K1):
alice_pub_sign_key_raw = b"""
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES/35y89DRx2XEh6pJvCckadQ9Awuys84
HORPVVaDksVxWfSkngYrz/c+HwVS9tV5ivnVwCHxyJ8gTQob/0LDDg==
-----END PUBLIC KEY-----
"""
alice_pub_sign_key = serialization.load_pem_public_key(alice_pub_sign_key_raw)

# Відкритий ключ Alice для узгодження ключа (значення x = xP), згенерований алгоритмом X25519, 
# закодований використовуючи функцію hexlify:
alice_x_pub_key = b'92ce3bc6d941238da92639c72a7d3bb483d3c18fdca9f42164459a3751638433'

# Підпис відкритого ключа Alice для узгодження ключа (для перевірки автентичності), 
# створений алгоримом ECDSA на кривій SECP256K1 та хеш-функції SHA-256, 
# закодований використовуючи функцію hexlify (включає обидва значення {r, s}):
signature_a = b'3045022034b7944bf92bfaa2791b5fe929d915add4ee59dbd9e776c1520568fbf2503048022100f09c9113f38fadb33b05332eab9a4982f7dda35fb1f503bb46da806c8e8dbaa2'

# Alice --> Bob:    alice_x_pub_key, signature_a, alice_pub_sign_key


#BOB
# Згенерувати довгострокову ключову пару для підпису алгоритмом ECDSA на кривій SECP256K1.
bob_priv_sign_key = ec.generate_private_key(
    ec.SECP256K1()
)
bob_pub_sign_key = bob_priv_sign_key.public_key()

# Згенерувати приватний ключ боба для узгодження ключа алгоритмом X25519.
bob_x_priv_key = X25519PrivateKey.generate()
bob_x_pub_key = bob_x_priv_key.public_key()

# Перевірити підпис відкритого ключа Alice для узгодження ключа (використовуючи відкритий ключ Alice для підпису).
try:
    alice_pub_sign_key.verify(
        binascii.unhexlify(signature_a),
        binascii.unhexlify(alice_x_pub_key),
        ec.ECDSA(hashes.SHA256())
    )
    print("Alice's signature was verified successfully")
except InvalidSignature:
    print("Alice's signature verification failed. Communication aborted")
    quit

# Створити відкритий ключ ECDH (значення Y = yP) для надсилання Alice
bob_sharegitd_value = bob_x_priv_key.exchange(
    X25519PublicKey.from_public_bytes(binascii.unhexlify(alice_x_pub_key))
)
print("\nShared secret value:\n", binascii.hexlify(bob_shared_value))

# Cтворити підпис значення Y використовуючи приватний довгостроковий ключ Боба для підпису.
signature_b = bob_priv_sign_key.sign(bob_shared_value, ec.ECDSA(hashes.SHA256()))


with open("bob_pub_sign_key.PEM", "wb") as f:
    f.write(bob_pub_sign_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

with open("bob_shared_value.hex", "wb") as f:
    f.write(binascii.hexlify(bob_shared_value))


with open("signature_b.hex", "wb") as f:
    f.write(binascii.hexlify(signature_b))    