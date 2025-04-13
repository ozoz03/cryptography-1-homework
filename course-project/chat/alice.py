import asyncio

from utils import alice_server, prompt, show, read_message_from_stdin, b64, hkdf, Ratchet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
import base64


async def receive(reader):
    """Receive data from other party"""
    while True:
        # Receive data from Bob (can be multiple messages)
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


async def init_connection(reader, writer):
    print("Connected with Bob!")
    prompt()

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
    print("IKb:", IKb)
    SPKb = await reader.read(32)
    SPKb = X25519PublicKey.from_public_bytes(SPKb)
    print("SPKb:", SPKb)
    OPKb = await reader.read(32)
    OPKb = X25519PublicKey.from_public_bytes(OPKb)
    print("OPKb:", OPKb)

    dh1 = IK.exchange(SPKb)
    dh2 = EK.exchange(IKb)
    dh3 = EK.exchange(SPKb)
    dh4 = EK.exchange(OPKb)
    # the shared key is KDF(DH1||DH2||DH3||DH4)
    sk = hkdf(dh1 + dh2 + dh3 + dh4, 32)
    print('Shared key:', b64(sk))
    # initialise the root chain with the shared key
    root_ratchet = Ratchet(sk)
    # initialise the sending and recving chains
    send_ratchet = Ratchet(root_ratchet.next()[0])
    recv_ratchet = Ratchet(root_ratchet.next()[0])
    print('recv ratchet:', list(map(b64, recv_ratchet.next())))
    print('send ratchet:', list(map(b64, send_ratchet.next())))

    await asyncio.gather(receive(reader), send(writer))


if __name__ == "__main__":
    print("Starting Alice's chat... Waiting for Bob...")
    asyncio.run(alice_server(init_connection))
