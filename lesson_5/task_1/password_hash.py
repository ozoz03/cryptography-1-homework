import bcrypt

def get_hash():
    pass1=b'qwertyuiop'
    pass2=b'sofPed-westag-jejzo1'
    pass3=b'f3Fg#Puu$EA1mfMx2'
    pass4=b'TIMCfJDkKBRm9/zwcFbHhE6zaMcSxR7nke1mJKcVqXpvCzg69d7Mf2quanMoAfmPJXyqT4gyGpLoL1lTHoqmwVmaUwrpOPRecB8GAU17eUJJHiksv3qrqcVxhgpMkX/UlKaLdFSwFIr7cVoJmBqQ/buWzxJNCIo7qbtIi3fSi62NwMHh'

	# gensalt's log_rounds parameter determines the complexity
	# the work factor is 2**log_rounds, and the default is 12
    salt = bcrypt.gensalt(
        rounds=10,
        prefix=b'2a'
        )
    
    hash1=bcrypt.hashpw(pass1, salt)
    hash2=bcrypt.hashpw(pass2, salt)
    hash3=bcrypt.hashpw(pass3, salt)
    hash4=bcrypt.hashpw(pass4, salt)

    print(hash1)
    print(hash2)
    print(hash3)
    print(hash4)

    # checking password 
    print(bcrypt.checkpw(pass1, hash1)) 
    print(bcrypt.checkpw(pass2, hash2)) 
    print(bcrypt.checkpw(pass3, hash3)) 
    print(bcrypt.checkpw(pass4, hash4)) 

get_hash() 
# b'$2a$10$EiemxF0KVaMph1S96taVZuLVkltwkrHORe21oTgElQ7.OpTJ9QYu6'
# b'$2a$10$EiemxF0KVaMph1S96taVZuM2318lgPosGifTGW8eK8HxitJMtNkpK'
# b'$2a$10$EiemxF0KVaMph1S96taVZusD9uEueMu0wVFzvkdZc9Yh.gQNJfuzG'
# b'$2a$10$EiemxF0KVaMph1S96taVZuz8ZH4X0T//uidWmKtGgBPMSQg3PNsiG'