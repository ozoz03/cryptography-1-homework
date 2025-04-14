import asyncio

from utils import alice_server, prompt, show, read_message_from_stdin, b64, hkdf, Ratchet, pad, unpad, KeyBundle, dh_ratchet_rotate
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
import base64
from Crypto.Cipher import AES


async def receive(reader, key_bundle):
    """Receive data from other party"""
    while True:
        bob_public_key = await reader.read(32)
        bob_public_key = X25519PublicKey.from_public_bytes(bob_public_key)
        # Receive data from Bob (can be multiple messages)
        data = await reader.read(1024)
        if not data:
            break

        # {DECRYPT HERE}
        # receive Bob's new public key and use it to perform a DH
        dh_ratchet_rotate(bob_public_key, key_bundle)
        key, iv = key_bundle.recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data))
        # print('Decrypted message:', msg)
        message = msg.decode()

        show(message)
        prompt()


async def send(writer,key_bundle):
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        # {ENCRYPT HERE}
        data = message.strip().encode()
        
        key, iv = key_bundle.send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data))
        print('Sending ciphertext to Bob:', b64(cipher))
        # send ciphertext and current DH public key
        writer.write(key_bundle.DHratchet.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw))
        # Send message
        writer.write(cipher)

        prompt()
        await writer.drain()


async def init_connection(reader, writer):

    # INITIAL EXCHANGE HERE
    IK = X25519PrivateKey.generate()
    EK = X25519PrivateKey.generate()

    writer.write(IK.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))
    writer.write(EK.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    IKb = await reader.read(32)
    IKb =  X25519PublicKey.from_public_bytes(IKb)
    SPKb = await reader.read(32)
    SPKb = X25519PublicKey.from_public_bytes(SPKb)
    OPKb = await reader.read(32)
    OPKb = X25519PublicKey.from_public_bytes(OPKb)

    dh1 = IK.exchange(SPKb)
    dh2 = EK.exchange(IKb)
    dh3 = EK.exchange(SPKb)
    dh4 = EK.exchange(OPKb)
    # the shared key is KDF(DH1||DH2||DH3||DH4)
    sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
    print('Shared key:', b64(sk))
    
    key_bundle = KeyBundle(sk)
    key_bundle.DHratchet = None

    # Initialise Alice's sending ratchet with Bob's public key
    PK = await reader.read(32)
    PK = X25519PublicKey.from_public_bytes(PK)
    dh_ratchet_rotate(PK, key_bundle)

    print("Connected with Bob!")
    prompt()
    await asyncio.gather(receive(reader,key_bundle), send(writer,key_bundle))


if __name__ == "__main__":
    print("Starting Alice's chat... Waiting for Bob...")
    asyncio.run(alice_server(init_connection))
