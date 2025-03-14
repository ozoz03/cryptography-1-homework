import os
import json
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def derive_key(username, password):
    salt = os.urandom(16)
    user =   {"username":username, 
              "salt":salt.hex(), 
              "length": 16, # 128 bit
              "iterations":1,
              "lanes":4,
              "memory_cost":64 * 1024,
              "ad":None,
              "secret":None}
    
    kdf = Argon2id(salt=salt,
                length=user["length"],
                iterations=user["iterations"],
                lanes=user["lanes"],
                memory_cost=user["memory_cost"],
                ad=user["ad"],
                secret=user["secret"])
    
    user["key"] = kdf.derive(password.encode("utf-8")).hex()
    return user


print(derive_key("John Doe", "qwed_112_32!D"))
