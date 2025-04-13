import asyncio

from utils import bob_client, show, prompt, read_message_from_stdin, b64, hkdf, Ratchet, pad, unpad, KeyBundle
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii
from Crypto.Cipher import AES


async def receive(reader, key_bundle):
    """Receive data from other party"""
    while True:
        alice_public_key = await reader.read(32)
        alice_public_key = X25519PublicKey.from_public_bytes(alice_public_key)
        
        # Receive data from Alice (can be multiple messages)
        data = await reader.read(1024)
        if not data:
            break

        # {DECRYPT HERE}
        # receive Alice's new public key and use it to perform a DH
        dh_ratchet(alice_public_key, key_bundle)
        key, iv = key_bundle.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data))
        # print('Decrypted message:', msg)
        show(msg.decode())
        prompt()


async def send(writer, key_bundle):
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        # {ENCRYPT HERE}
        data = message.strip().encode()

        key, iv = key_bundle.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data))
        print('Sending ciphertext to Alice:', b64(cipher))
        # send current DH public key to Alice
        writer.write(key_bundle.DHratchet.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw))
        # Send message
        writer.write(cipher)

        prompt()
        await writer.drain()


async def init_connection():
    reader, writer = await bob_client()

    # INITIAL EXCHANGE HERE
    IKa = await reader.read(32)
    IKa = X25519PublicKey.from_public_bytes(IKa)
    EKa = await reader.read(32)
    EKa =  X25519PublicKey.from_public_bytes(EKa)

    IK = X25519PrivateKey.generate()
    SPK = X25519PrivateKey.generate()
    OPK = X25519PrivateKey.generate()

    writer.write(IK.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    writer.write(SPK.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    writer.write(OPK.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    # 4 Diffie Hellman exchanges (X3DH)
    dh1 = SPK.exchange(IKa)
    dh2 = IK.exchange(EKa)
    dh3 = SPK.exchange(EKa)
    dh4 = OPK.exchange(EKa)
    # the shared key is KDF(DH1||DH2||DH3||DH4)
    sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
    print('Shared key:', b64(sk))

    key_bundle = KeyBundle(sk)
    
    writer.write(key_bundle.DHratchet.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    print("Connected to Alice!")
    prompt()
    await asyncio.gather(receive(reader, key_bundle), send(writer,key_bundle))

def dh_ratchet(alice_public, key_bundle):
    # perform a DH ratchet rotation using Alice's public key
    dh_recv = key_bundle.DHratchet.exchange(alice_public)
    shared_recv = key_bundle.root_ratchet.next(dh_recv)[0]
    # use Alice's public and our old private key
    # to get a new recv ratchet
    key_bundle.recv_ratchet = Ratchet(shared_recv)
    print('Recv ratchet seed:', b64(shared_recv))
    # generate a new key pair and send ratchet
    # our new public key will be sent with the next message to Alice
    key_bundle.DHratchet = X25519PrivateKey.generate()
    dh_send = key_bundle.DHratchet.exchange(alice_public)
    shared_send = key_bundle.root_ratchet.next(dh_send)[0]
    key_bundle.send_ratchet = Ratchet(shared_send)
    print('Send ratchet seed:', b64(shared_send))

if __name__ == "__main__":
    print("Starting Bob's chat...")
    asyncio.run(init_connection())
