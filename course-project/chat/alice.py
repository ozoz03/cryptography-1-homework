import asyncio

from utils import alice_server, prompt, show, read_message_from_stdin, b64, hkdf, Ratchet, pad, unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
import base64
from Crypto.Cipher import AES

DHratchet = None
root_ratchet = None
recv_ratchet = None
send_ratchet = None

async def receive(reader):
    global DHratchet
    global root_ratchet
    global recv_ratchet
    global send_ratchet
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
        dh_ratchet(bob_public_key)
        key, iv = recv_ratchet.next()
        # decrypt the message using the new recv ratchet
        msg = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data))
        print('Decrypted message:', msg)
        message = msg.decode()

        show(message)
        prompt()


async def send(writer):
    global DHratchet
    global root_ratchet
    global recv_ratchet
    global send_ratchet
    """Send data to other party"""
    while True:
        message = await read_message_from_stdin()

        # {ENCRYPT HERE}
        data = message.strip().encode()
        
        key, iv = send_ratchet.next()
        cipher = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data))
        print('Sending ciphertext to Bob:', b64(cipher))
        # send ciphertext and current DH public key
        writer.write(DHratchet.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw))
        # Send message
        writer.write(cipher)

        prompt()
        await writer.drain()


async def init_connection(reader, writer):
    global DHratchet
    global root_ratchet
    global recv_ratchet
    global send_ratchet
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

    # Initialise Alice's sending ratchet with Bob's public key
    PK = await reader.read(32)
    PK = X25519PublicKey.from_public_bytes(PK)
    dh_ratchet(PK)

    await asyncio.gather(receive(reader), send(writer))

def dh_ratchet(bob_public):
    global DHratchet
    global root_ratchet
    global recv_ratchet
    global send_ratchet
    # perform a DH ratchet rotation using Bob's public key
    if DHratchet is not None:
        # the first time we don't have a DH ratchet yet
        dh_recv = DHratchet.exchange(bob_public)
        shared_recv = root_ratchet.next(dh_recv)[0]
        # use Bob's public and our old private key
        # to get a new recv ratchet
        recv_ratchet = Ratchet(shared_recv)
        print('Recv ratchet seed:', b64(shared_recv))
    # generate a new key pair and send ratchet
    # our new public key will be sent with the next message to Bob
    DHratchet = X25519PrivateKey.generate()
    dh_send = DHratchet.exchange(bob_public)
    shared_send = root_ratchet.next(dh_send)[0]
    send_ratchet = Ratchet(shared_send)
    print('Send ratchet seed:', b64(shared_send))

if __name__ == "__main__":
    print("Starting Alice's chat... Waiting for Bob...")
    asyncio.run(alice_server(init_connection))
