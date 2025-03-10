import random

def random_generator(filename):
    afile = open(filename, "wb" )

    for i in range(1000000000):
        line = random.randbytes(32)
        # print(line)
        afile.write(line)

    afile.close()  


random_generator("random.bin")
