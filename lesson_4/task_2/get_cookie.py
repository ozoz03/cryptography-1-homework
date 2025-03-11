import requests
import json
from datetime import datetime, timedelta

def get_cookie():
    # hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org/flipping_cookie/get_cookie/"
    r = requests.get(url)
    ct = (json.loads(r.text))["cookie"]
    return ct


def check_admin(cookie,iv):
    # hex = hexlify(pt.encode()).decode()
    url = "http://aes.cryptohack.org//flipping_cookie/check_admin/" + cookie + "/"+ iv
    r = requests.get(url)
    return r.text


def get_flag():
    cookie = get_cookie()
    print("cookie:", cookie)
    iv = bytes.fromhex(cookie[:32])
    
    
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%S")
    plain = b"admin=False;00000"
    dc0 = [0]*16
    for i in range(len(dc0)):
        dc0[i] = iv[i] ^ plain[i]
    
    
    f = b"admin=True;00000"
    iv_2 = [0]*16
    for i in range(len(iv_2)):
        iv_2[i] = dc0[i] ^ f[i]
         
    print(check_admin(cookie=cookie[32:], iv=bytes(iv_2).hex()))


get_flag()
#FLAG={"flag":"crypto{4u7h3n71c4710n_15_3553n714l}"}    
    