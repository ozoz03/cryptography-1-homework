import requests
import json
import string

from binascii import hexlify


def encrypt(pt):
    """Obtain ciphertext (encryption) for plaintext"""
    print("        0123456789abcdef0123456789abcdef")
    print("Payload:"+"".join(pt))
    hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org/ecb_oracle/encrypt/" + hex
    r = requests.get(url)
    ct = (json.loads(r.text))["ciphertext"]
    return ct


def print_ciphertext(ct):
    """Print ciphertext by block"""
    parts = [ct[i : i + 32] for i in range(0, len(ct), 32)]
    for p in parts:
        print(p)

def get_flag():  
           #0123456789abcdef0123456789abcdef
    # text="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    # text="AAAAAAAAAAAAAAAcAAAAAAAAAAAAAAA"
    # text="AAAAAAAAAAAAAAcrAAAAAAAAAAAAAA"
    # text="AAAAAAAAAAAAAcryAAAAAAAAAAAAA"
    ascii_list=string.printable
    print("".join(ascii_list))
    flag=[]
    for i in range(15,-1,-1):
        print(i)
        for j in range(len(ascii_list)):
            c=ascii_list[j] 
            payload=["A"]*i + flag + [c] + ["A"]*i 
            ct = encrypt("".join(payload))
            parts = [ct[i : i + 32] for i in range(0, len(ct), 32)]
            if parts[0]==parts[1]:
                print("Found!")
                flag.append(c)
                print("".join(flag))
                break
            j+=1
get_flag()
#FLAG=crypto{p3n6u1n5_