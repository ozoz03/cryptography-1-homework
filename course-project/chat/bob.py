import asyncio

from utils import bob_client, show, prompt, read_message_from_stdin, b64, hkdf, Ratchet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii


async def receive(reader):
    """Receive data from other party"""
    while True:
        # Receive data from Alice (can be multiple messages)
        data = await reader.read(1024)
        if not data:
            break

        # {DECRYPT HERE}
        message = data.decode()

        show(message)
        prompt()


async def send(writer):
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        # {ENCRYPT HERE}
        data = message.strip().encode()

        # Send message
        writer.write(data)

        prompt()
        await writer.drain()


async def init_connection():
    reader, writer = await bob_client()
    print("Connected to Alice!")
    prompt()

    # INITIAL EXCHANGE HERE
    IKa = await reader.read(32)
    IKa = X25519PublicKey.from_public_bytes(IKa)
    print("IKa:", IKa) 
    EKa = await reader.read(32)
    EKa =  X25519PublicKey.from_public_bytes(EKa)
    print("EKa:", EKa)           

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

    # initialise the root chain with the shared key
    root_ratchet = Ratchet(sk)
    # initialise the sending and recving chains
    recv_ratchet = Ratchet(root_ratchet.next()[0])
    send_ratchet = Ratchet(root_ratchet.next()[0])
    print('recv ratchet:', list(map(b64, recv_ratchet.next())))
    print('send ratchet:', list(map(b64, send_ratchet.next())))

    await asyncio.gather(receive(reader), send(writer))


if __name__ == "__main__":
    print("Starting Bob's chat...")
    asyncio.run(init_connection())
