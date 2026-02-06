import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number



"""
=============================
Task 2
=============================
"""

def s_to_bytes(s): # converts s to bytes just a helper
    if s == 0:
        return b"\x00"
    return s.to_bytes((s.bit_length() + 7) // 8, "big")

def derive_key(s): # finds 128bit keys from the sha256
    h = SHA256.new()
    h.update(s_to_bytes(s))
    return h.digest()[:16]
def try_decrypt(key, iv, cipher):
    try:
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(cipher), 16)
        return pt
    except ValueError:
        return None

def TASK2_part1():
    """

    mallory is able to send q in place of Y1 and Y2 so alice and bob both end up with s = 0

    """
    qhex = """
B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
DF1FB2BC 2E4A4371
"""
    ahex = """
A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
855E6EEB 22B3B2E5
"""
    # public a and q
    q = int("".join(qhex.split()), 16)
    a = int("".join(ahex.split()), 16)
    # private x1 x2
    X1 = random.randint(1, q-1) 
    X2 = random.randint(1, q-1)
    # public y1 y2, in the attack these are the ones that get intercepted by mallory and she sends q instead
    Y1 = pow(a, X1, q)  # alice to mallory
    Y2 = pow(a, X2, q)  # bob to mallory
    Y1_for_bob = q # mallory will send q to bob 
    Y2_for_alice = q # mallory will send q to alice
    s_alice = pow(Y2_for_alice, X1, q) # 0
    s_bob = pow(Y1_for_bob, X2, q) # 0
    print("s computed by alice:", s_alice)
    print("s computed by bob:  ", s_bob)
    s_mallory = 0 # mallory knows s is 0
    # they will all have the same key as mallory knows s is 0
    key_alice = derive_key(s_alice)
    key_bob   = derive_key(s_bob)
    key_mall  = derive_key(s_mallory)
    print("does alice key == bob key", key_alice == key_bob)
    print("does alice key == mallory key", key_alice == key_mall)

    """
    simulating situation where alice sends to bob, everyone has the same key (s = 0), so alice will send cipher text to bob, mallory will be able to see too
    """

    #alice
    IV = get_random_bytes(16)
    pt = b"hello bob, this is alice"
    cipher_alice = AES.new(key_alice, AES.MODE_CBC, IV)
    ciphertext = cipher_alice.encrypt(pad(pt, 16))

    print("alice sends IV + ciphertext:", IV.hex(), ciphertext.hex())
    # bob decypt
    cipher_bob = AES.new(key_bob, AES.MODE_CBC, IV)
    decrypted_bob = unpad(cipher_bob.decrypt(ciphertext), 16)
    print("bob decrypted message:", decrypted_bob)

    # mallory has s so can decrypt too
    cipher_mallory = AES.new(key_mall, AES.MODE_CBC, IV)
    decrypted_mallory = unpad(cipher_mallory.decrypt(ciphertext), 16)
    print("mallory decrypted message:", decrypted_mallory)




def TASK2_part2(a_in):
    """
    part 2, repeat attack  but tamper with generator a, mallory can recover messages from the cipher texts by setting a to 1

    pseudo:

    by tampering with a, mallory can narrow down s into like 3 possabilities 1, q, or q-1

    when we know s we can derive the keys

    """
    qhex = """
B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6
9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0
13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70
98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0
A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708
DF1FB2BC 2E4A4371
"""
    ahex = """
A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F
D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213
160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1
909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A
D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24
855E6EEB 22B3B2E5
"""

    q = int("".join(qhex.split()), 16)
    a_real = int("".join(ahex.split()), 16)

    # tampering happens here
    if a_in == "1":
        a = 1
    elif a_in == "q":
        a = q
    elif a_in == "q-1":
        a = q - 1
    print("a:", a)
    xA = random.randint(1, q - 1)
    xB = random.randint(1, q - 1)

    # public using tampered alpha
    yA = pow(a, xA, q)
    yB = pow(a, xB, q)

    # using tampered yA and yB
    sA = pow(yB, xA, q)
    sB = pow(yA, xB, q)

    keyA = derive_key(sA) # alice key
    keyB = derive_key(sB) # bob key

    alice_to_bob = b"bob wassup brodigy you looking so fresh" # alice sends to bob
    iv_alice_to_bob = get_random_bytes(16)
    cipher_1 = AES.new(keyA, AES.MODE_CBC, iv_alice_to_bob).encrypt(pad(alice_to_bob, 16))

    bob_to_alice = b"thanks alice i am feeling so fresh" # bob responds
    iv_bob_to_alice = get_random_bytes(16)
    cipher_2 = AES.new(keyB, AES.MODE_CBC, iv_bob_to_alice).encrypt(pad(bob_to_alice, 16))

    print("alice->bob:", iv_alice_to_bob.hex(), cipher_1.hex())
    print("bob->alice:", iv_bob_to_alice.hex(), cipher_2.hex())

    if a_in in {"1", "q"}: # mallory knows s if a = 1 or q we know s is 1 or 0 respectively
        mallory_s = 1 if a_in == "1" else 0
        mallory_key = derive_key(mallory_s) # gets key
        loot_1 = try_decrypt(mallory_key, iv_alice_to_bob, cipher_1) # first message
        loot_2 = try_decrypt(mallory_key, iv_bob_to_alice, cipher_2) # second message
        print("mallory s:", mallory_s)
        print("got message 1:", loot_1)
        print("got message 2:", loot_2)
    else: # means a = q-1, meaning s is either 1 or q-1, you kind of have to see both and see which has padding or not
        if yA == 1 or yB == 1:
            mallory_s = 1
        else:
            mallory_s = q - 1

        candidates = [1, q - 1] # set and than try both
        best0 = best1 = None 
        chosen = None

        for s_guess in candidates:
            key_guess = derive_key(s_guess) 
            try1 = try_decrypt(key_guess, iv_alice_to_bob, cipher_1)
            try2 = try_decrypt(key_guess, iv_bob_to_alice, cipher_2)# try both keys
            if try1 is not None and try2 is not None:
                best0, best1 = try1, try2
                chosen = s_guess
                break

        print("s:", chosen)
        print("recovered message 1:", best0)
        print("recovered message 2:", best1)


"""
=============================
Task 3
=============================
"""

def TASK3(n_length):

    if n_length > 2048:
        ValueError("too big")
    
    e = 65537
    n = number.getPrime(n_length)

    print("alice sends e and n:", e, n)







if __name__ == "__main__":
    TASK2_part2("q")
