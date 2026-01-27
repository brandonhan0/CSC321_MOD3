# Bryce Wang and Brandon Han :)

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import random

def dh_Key_Ex():
    """Implements Diffie-Hellman Key Exchange
    1 denotes Alice, 2 denotes Bob
    """
    q = 37 # must be prime
    a = 5 # smaller than q and a primitive root of q


    X1 = random.randint(0, q)
    X2 = random.randint(0, q)

    Y1 = pow(a, X1, q)
    Y2 = pow(a, X2, q)

    s1 = pow(Y2, X1, q)
    s2 = pow(Y1, X2, q)

    k1 = SHA256.new()
    k2 = SHA256.new()
    k1.update(int.to_bytes(s1))
    k2.update(int.to_bytes(s2))

    print(f"Does this work: {s1} {s2} \n {k1.digest()} \n {k2.digest()}")

    return

if __name__ == "__main__":
    print("hello")
    dh_Key_Ex()