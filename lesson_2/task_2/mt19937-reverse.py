import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from PIL import Image,UnidentifiedImageError



class MT19937Reverse:
    """Reverses the Mersenne Twister based on 624 observed outputs.

    The internal state of a Mersenne Twister can be recovered by observing
    624 generated outputs of it. However, if those are not directly
    observed following a twist, another output is required to restore the
    internal index.

    See also https://en.wikipedia.org/wiki/Mersenne_Twister#Pseudocode .

    """

    def unshiftRight(self, x, shift):
        res = x
        for i in range(32):
            res = x ^ res >> shift
        return res

    def unshiftLeft(self, x, shift, mask):
        res = x
        for i in range(32):
            res = x ^ (res << shift & mask)
        return res

    def untemper(self, v):
        """Reverses the tempering which is applied to outputs of MT19937"""

        v = self.unshiftRight(v, 18)
        v = self.unshiftLeft(v, 15, 0xEFC60000)
        v = self.unshiftLeft(v, 7, 0x9D2C5680)
        v = self.unshiftRight(v, 11)
        return v

    def reverse(self, outputs, forward=True):
        """Reverses the Mersenne Twister based on 624 observed values.

        Args:
            outputs (List[int]): list of >= 624 observed outputs from the PRNG.
                However, >= 625 outputs are required to correctly recover
                the internal index.
            forward (bool): Forward internal state until all observed outputs
                are generated.

        Returns:
            Returns a random.Random() object.
        """

        result_state = None

        assert len(outputs) >= 624  # need at least 624 values

        ivals = []
        for i in range(624):
            ivals.append(self.untemper(outputs[i]))

        if len(outputs) >= 625:
            # We have additional outputs and can correctly
            # recover the internal index by bruteforce
            challenge = outputs[624]
            for i in range(1, 626):
                state = (3, tuple(ivals + [i]), None)
                r = random.Random()
                r.setstate(state)

                if challenge == r.getrandbits(32):
                    result_state = state
                    print("State was found!")
                    break
        else:
            # With only 624 outputs we assume they were the first observed 624
            # outputs after a twist -->  we set the internal index to 624.
            result_state = (3, tuple(ivals + [624]), None)

        rand = random.Random()
        rand.setstate(result_state)

        if forward:
            for i in range(624, len(outputs)):
                assert rand.getrandbits(32) == outputs[i]

        return rand


def decrypt(filename, key):
    key_bytes = key.to_bytes(16, "little")

    with open(filename, "rb") as f:
        data = bytearray(f.read())

    cipher = Cipher(algorithms.AES128(key_bytes), modes.ECB())
    decryptor = cipher.decryptor()
    padder = padding.PKCS7(128).unpadder()
    padded_data = padder.update(data)
    data = decryptor.update(padded_data) + decryptor.finalize()

    return data


def getkey(filename):
    
    my_file = open(filename, "r") 
    data = my_file.read() 
    data_into_list = data.replace(' ', '').replace('[', '').replace(']', '').split(",") 
    my_file.close()

    int_list = list(map(int, data_into_list))
    print(int_list)
    reverse=MT19937Reverse()
    rand=reverse.reverse(outputs=int_list,forward=True) 

    for i in range(624):
        key=rand.getrandbits(128)

        data = decrypt(".\homework\data.bmp.enc",key)
        with open(".\homework\data.bmp", "wb") as f:
            f.write(data)

        print(key)

        try:
            img = Image.open(".\homework\data.bmp")
            print(img.format)
            print(hex(key))
            break        
        except UnidentifiedImageError:
            print("decripted file is not image")
        except:
            print("Something else went wrong")
            


getkey(".\homework\sequence.txt")    