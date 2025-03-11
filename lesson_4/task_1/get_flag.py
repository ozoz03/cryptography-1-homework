import requests
import json
from binascii import hexlify

def encrypt(pt):
    # print("        0123456789abcdef0123456789abcdef")
    # print("Payload:"+"".join(pt))
    # hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org/lazy_cbc/encrypt/" + pt
    r = requests.get(url)
    ct = (json.loads(r.text))["ciphertext"]
    return ct


def receive(pt):
    # print("Payload:"+"".join(pt))
    # hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org/lazy_cbc/receive/" + pt
    r = requests.get(url)
    ct = (json.loads(r.text))["error"].replace("Invalid plaintext: ","")
    return ct


def get_flag(pt):
    # print("Payload:"+"".join(pt))
    # hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org/lazy_cbc/get_flag/" + pt
    r = requests.get(url)
    ct = (json.loads(r.text))["plaintext"]
    return ct

def resolve_flag():
    # plain = (b'0'*(16*3)).hex()
    # print("plain:",plain)
    # cipher = encrypt(plain)
    # print("cipher:",cipher)
    # fake_cipher = cipher[:32] + '0'*32 + cipher[:32] 
    # print("fake_cipher:",fake_cipher)
    # fake_plain=receive(fake_cipher)
    # print("received:",fake_plain)
    # fake_plain = bytes.fromhex(fake_plain)
    # iv = [0]*16
    # for i in range(len(iv)):
    #     iv[i] = fake_plain[i] ^ fake_plain[32+i] 
    # print("iv:",bytes(iv).hex())
    # # key="".join(str(x) for x in iv)
    # # print("key:",key)
    # flag = get_flag(bytes(iv).hex())
    # # print(bytes.fromhex(flag))
    # print(flag)
    # print(bytes.fromhex(flag))
    
    # plain = (b'a'*(16*2)).hex()
    # print("plain:",plain)
    # cipher = encrypt(plain)
    # print("cipher:",cipher)
    # print('---')
    # fake_cipher = cipher[:32] + '0'*32 + cipher[:32] 
    # print("fake_cipher:",fake_cipher)


    fake_plain=receive('0'*(32*3))
    print("received:",fake_plain)
    fake_plain = bytes.fromhex(fake_plain)
    iv = [0]*16
    for i in range(len(iv)):
        iv[i] = fake_plain[i] ^ fake_plain[16+i] 
    print("iv:",bytes(iv).hex())
    flag = get_flag(bytes(iv).hex())
    print(flag)
    print(bytes.fromhex(flag))


resolve_flag()
#FLAG=crypto{50m3_p30pl3_d0n7_7h1nk_IV_15_1mp0r74n7_?} 