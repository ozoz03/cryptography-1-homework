import asyncio
import signal
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
import base64


YOUR_PROMPT = "\033[32m" + ">>> " + "\033[0m"
THEIR_PROMPT = "\033[31m" + "\n<<< " + "\033[0m"
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888
MAX_LEN = 1024


def prompt():
    """Show prompt for message"""
    print(YOUR_PROMPT, end="", flush=True)


def show(msg):
    """Print received message

    Args:
        msg (str|bytes): received message in bytes or decoded str.
    """
    if isinstance(msg, bytes):
        msg = msg.decode()
    print(f"{THEIR_PROMPT}{msg}", flush=True)


async def read_message_from_stdin():
    """Read message to be sent from command line"""
    return await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)


async def alice_server(handler):
    loop = asyncio.get_running_loop()
    # loop.add_signal_handler(signal.SIGINT, lambda: sys.exit(0))

    # Alice runs the server
    server = await asyncio.start_server(
        lambda r, w: handler(r, w), SERVER_HOST, SERVER_PORT
    )
    async with server:
        await server.serve_forever()


async def bob_client():
    loop = asyncio.get_running_loop()
    # loop.add_signal_handler(signal.SIGINT, lambda: sys.exit(0))

    # Bob connects to Alice
    return await asyncio.open_connection(SERVER_HOST, SERVER_PORT)


def b64(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode('utf-8').strip()

def hkdf(inp, length):
    # use HKDF on an input to derive a key
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=b'',
                info=b'', backend=default_backend())
    return hkdf.derive(inp)

class Ratchet(object):
    def __init__(self, key):
        self.state = key

    def next(self, input=b''):
        # turn the ratchet to change the state
        output = hkdf(self.state + input, 80)
        self.state = output[:32]
        outkey, iv = output[32:64], output[64:]
        return outkey, iv    


class KeyBundle(object):
    def __init__(self, sk):
         # initialise the root chain with the shared key
        self.root_ratchet = Ratchet(sk)
        # initialise the sending and recving chains
        self.recv_ratchet = Ratchet(self.root_ratchet.next()[0])
        self.send_ratchet = Ratchet(self.root_ratchet.next()[0])
        print('recv ratchet:', list(map(b64, self.recv_ratchet.next())))
        print('send ratchet:', list(map(b64, self.send_ratchet.next())))
        self.DHratchet = X25519PrivateKey.generate()
   
def pad(msg):
    # pkcs7 padding
    num = 16 - (len(msg) % 16)
    return msg + bytes([num] * num)

def unpad(msg):
    # remove pkcs7 padding
    return msg[:-msg[-1]]


def dh_ratchet_rotate(public_key, key_bundle):
    if key_bundle.DHratchet is not None:
            # the first time we don't have a DH ratchet yet
            dh_recv = key_bundle.DHratchet.exchange(public_key)
            shared_recv = key_bundle.root_ratchet.next(dh_recv)[0]
            # use the public and our old private key
            # to get a new recv ratchet
            key_bundle.recv_ratchet = Ratchet(shared_recv)
            print('Recv ratchet seed:', b64(shared_recv))
    key_bundle.DHratchet = X25519PrivateKey.generate()
    dh_send = key_bundle.DHratchet.exchange(public_key)
    shared_send = key_bundle.root_ratchet.next(dh_send)[0]
    key_bundle.send_ratchet = Ratchet(shared_send)
    print('Send ratchet seed:', b64(shared_send))    
