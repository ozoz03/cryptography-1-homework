from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import hashlib, os

values = [91911, 90954, 95590, 97390, 96578, 97211, 95090]


class Block:
    def __init__(self, index, data, prev_hash):
        self.index = index
        self.data = data
        self.prev_hash = prev_hash
        self.hash = None
        self.nonce = None

def hash(data, prev_hash, nonce):
    return hashlib.sha256(f"{data}{prev_hash}{nonce}".encode()).hexdigest()

def mine_block(block, difficulty):
    while True:
        block.nonce = os.urandom(16)
        block.hash = hash(block.data, block.prev_hash, block.nonce)
        if block.hash.startswith('0' * difficulty):
            block.hash = block.hash
            return block
        print(block.hash)
    return 0

def add_block(blockchain, block):
    block = mine_block(block, 3)
    blockchain.append(block)
    return blockchain


blockchain = []
i= 0
print(type(blockchain))
for value in values:
    prev_hash=blockchain[-1].hash if blockchain else ""
    block = Block(index=i, data=value,prev_hash=prev_hash)
    blockchain = add_block(blockchain, block)
    i += 1

for block in blockchain:
    print(f"Index: {block.index}, Data: {block.data}, Prev Hash: {block.prev_hash}, Hash: {block.hash}, Nonce: {block.nonce.hex()}")   