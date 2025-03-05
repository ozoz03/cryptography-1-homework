import random

def random_generator(filename):
    afile = open(filename, "wb" )

    for i in range(1000000000):
        line = (random.randint(1, 1000000000)).to_bytes(4,'big')
        # print(line)
        afile.write(line)

    afile.close()  


random_generator("random.bin")
