from binascii import hexlify

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

# Загальні параметри DH спільні для всіх учасників і узгоджуються на рівні протоколу.
print("Generating parameters...")
parameters = dh.generate_parameters(generator=2, key_size=2048)
print("\nModule:\n", parameters.parameter_numbers().p)
print("\nGen:", parameters.parameter_numbers().g)

# Alice
alice_private_key = parameters.generate_private_key()  # a
alice_public_key = alice_private_key.public_key()  # g^a
# Alice auth Key generation
print("Generating Alice auth key...")
alice_auth_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
alice_auth_public_key = alice_auth_private_key.public_key()
print("Signing Alice public key...")
alice_signature = alice_auth_private_key.sign(
        alice_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

# Bob

bob_private_key = parameters.generate_private_key()  # b
bob_public_key = bob_private_key.public_key()  # g^b

# Bob auth Key generation
print("Generating Bob auth key...")
bob_auth_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
bob_auth_public_key = bob_auth_private_key.public_key()
print("Signing Bob public key...")
bob_signature = bob_auth_private_key.sign(
        bob_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

# Alice --> Bob:    alice_public_key, alice_auth_public_key, alice_signature
# Bob --> Alice:    bob_public_key, bob_auth_public_key, bob_signature

# Alice
try:
    bob_auth_public_key.verify(
        bob_signature,
        bob_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Bob's signature was verified successfully")
except InvalidSignature:
    print("Bob's signature verification failed. Communication aborted")
    quit

alice_shared_value = alice_private_key.exchange(bob_public_key)
print("\nShared secret value:\n", hexlify(alice_shared_value))
alice_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
    info=b"handshake data",
).derive(alice_shared_value)
print("\nDerived secret key:\n", hexlify(alice_derived_key))

# Bob
try:
    alice_auth_public_key.verify(
        alice_signature,
        alice_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Alice's signature was verified successfully")
except InvalidSignature:
    print("Alice's signature verification failed. Communication aborted")
    quit

bob_shared_value = bob_private_key.exchange(alice_public_key)
print("\nShared secret value:\n", hexlify(bob_shared_value))
bob_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
    info=b"handshake data",
).derive(bob_shared_value)

print("\nDerived secret key:\n", hexlify(bob_derived_key))
print("\nShared values equal?\t", alice_shared_value == bob_shared_value)
print("Shared keys equal?\t", alice_derived_key == bob_derived_key)
