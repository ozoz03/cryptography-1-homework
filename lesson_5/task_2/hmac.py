from Crypto.Hash import HMAC, SHA256
import os

key_cr = b'63e353ae93ecbfe00271de53b6f02a46'
plain =b'76c3ada7f1f7563ff30d7290e58fb4476eb12997d02a6488201c075da52ff3890260e2c89f631e7f919af96e4e47980a'
iv = b'75b777fc8f70045c6006b39da1b3d622'

def xor(p1, p2):
    result_length = len(p1)
    if len(p2)>len(p1):
        result_length = len(p2)
        p1.resize(len(p2))
    else:
        p2.resize(len(p1))

    result = [0]*result_length
    for i in range(len(iv)):
        result[i] = p1[i] ^ p2[i] 
    return result


def get_message_hash(message,secret,cr_key,iv):
    msg={"message": message,"key":cr_key,"iv":iv,"secret":secret.hex()}
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(message)
    msg["hmac"]=h.hexdigest()

    return msg


secret = os.urandom(16)
print(get_message_hash(plain,secret=secret, cr_key=key_cr,iv=iv))