import secrets

def secrets_generator(filename):
    afile = open(filename, "wb" )

    for i in range(1000000000):
        afile.write(secrets.randbits(32).to_bytes(4,'big'))

    afile.close()  


secrets_generator("secrets.bin")
