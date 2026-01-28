# Bryce Wang and Brandon Han :)

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import random
from Crypto.Util.Padding import pad, unpad

def dh_Key_Ex():
    """Implements Diffie-Hellman Key Exchange
    In a given variable, 1 denotes Alice, 2 denotes Bob
    """
    qhex = """ 
B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
DF1FB2BC 2E4A4371
""" # must be a prime number

    ahex = """
A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
855E6EEB 22B3B2E5
""" # smaller than q and a primitive root of q

    q = int("".join(qhex.split()), 16)
    a = int("".join(ahex.split()), 16)

    X1 = random.randint(0, q)
    X2 = random.randint(0, q)

    Y1 = pow(a, X1, q)
    Y2 = pow(a, X2, q)

    s1 = pow(Y2, X1, q)
    s2 = pow(Y1, X2, q)

    k1 = SHA256.new()
    k2 = SHA256.new()
    k1.update(s1.to_bytes((s1.bit_length() + 7) // 8, "big"))
    k2.update(s2.to_bytes((s2.bit_length() + 7) // 8, "big"))

    key1 = k1.digest()[:16]
    key2 = k2.digest()[:16]

    IV = get_random_bytes(16)

    text = b"yay this works"

    c1 = AES.new(key1, AES.MODE_CBC, IV)
    ciphertext = c1.encrypt(pad(text, 16))

    print("Alice sends ciphertext:", ciphertext)

    c2 = AES.new(key2, AES.MODE_CBC, IV)
    decrypted_text = unpad(c2.decrypt(ciphertext), 16)

    print("Bob received:", decrypted_text)

    return

if __name__ == "__main__":

    dh_Key_Ex()