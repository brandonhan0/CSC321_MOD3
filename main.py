import random
import math, hashlib
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number

"""
=============================
Task 1 - MOD2
=============================
"""


def pad(data):
   pad_len = 16 - (len(data) % 16) # sees how much we missing at the end
   return data + bytes([pad_len]) * pad_len # does the pk7 pad


def xorring(a, b):
   return bytes(x ^ y for x, y in zip(a, b)) # literally just xors byte by byte


def ECB(key, thing):
   aes = AES.new(key, AES.MODE_ECB) #we can use this byte by byte
   out = bytearray() #set output type bc its being lame
   for i in range(0, len(thing), 16): # for each 16 bytes for 128 bit chunks
       block = thing[i:i+16] # slices for the following 128 bits
       out += aes.encrypt(block) # encrypts this block only and add it to total
   return bytes(out) # returns the thing


def CBC(key, iv, thing):
   aes = AES.new(key, AES.MODE_ECB) # gets key cipher
   out = bytearray() # typedef
   prev = iv # previous for CBC method
   for i in range(0, len(thing), 16): # 128 bit blocks
       block = thing[i:i+16] # collect the data
       x = xorring(block, prev) # XOR first
       c = aes.encrypt(x) # encrypt
       out += c # add each
       prev = c # save prev for the method
   return bytes(out) # returns thing


def TASK1(input, output, mode):
   key = get_random_bytes(16)
   iv = get_random_bytes(16)


   with open(input, "rb") as f:
       pt = f.read(54)
       text = f.read()


   thing = pad(text)


   if mode == "ECB":
       out = ECB(key, thing)
   elif mode == "CBC":
       out = CBC(key, iv, thing)


   with open(output, "wb") as f:
       f.write(pt)
       f.write(out)


   return key, iv


"""
=============================
Task 2
=============================
"""




def decrypt(key, IV, text):
  cipher = AES.new(key, AES.MODE_CBC, IV)
  return cipher.decrypt(text)


def submit(user_in, key, IV):
  if isinstance(user_in, str):
      user_in = user_in.encode("utf-8") # encode if string
  else:
      user_in = bytes(user_in) # otherwise just bytes
  start = b"userid=456; userdata= " # prepend
  end   = b";session-id=31337" + b";hello-there=42" # append str
  new_in = user_in.replace(b";", b"%3B").replace(b"=", b"%3D") # url sub
  together = pad(start + new_in + end) # pad
  final = CBC(key, IV, together)
  with open("submit.txt", "wb") as f:
      f.write(final)
  return final

def verify(text, key, IV):
  aes = AES.new(key, AES.MODE_CBC, IV)
  pt = aes.decrypt(text)
  return b";admin=true;" in pt

def bit_attack(IV, key):
  start = b"userid=456; userdata= "
  start_len = len(start) # important to identify which bit we need to flip

  pad_to_start = (16 - (start_len % 16)) % 16  # we need the user input to be the beginning of a 16 byte block
  input = b"L" * (pad_to_start + 16)  # one full known block of L important

  ct = bytearray(submit(input, key, IV)) # cipher test of the pt

  target_plain_start = start_len + pad_to_start # where the user text starts after prefix and padding
  target_block = target_plain_start // 16 # start byte in the block
  prev_block_start = (target_block - 1) * 16 # beginning of cipher text inside the byte array; we edit this to get admin true

  desired  = b";admin=true;" + b"L" * (16 - len(b";admin=true;")) # editing plain text to have admin true
  original = b"L" * 16

  for j in range(16):
      ct[prev_block_start + j] ^= (original[j] ^ desired[j]) # 

  return bytes(ct)


if __name__ == "__main__":
   key = get_random_bytes(16)
   IV  = get_random_bytes(16)


   normal = submit("hello", key, IV)
   print("verify:", verify(normal, key, IV))  # should be False


   bad = bit_attack(IV, key)
   print("verify:", verify(bad, key, IV))
#    TASK1("mustang.bmp", "output.bmp", "CBC")


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

def unpad(padded):
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("bad padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bad padding bytes")
    return padded[:-pad_len]

def AES_CBC_encrypt_sendable(key, plaintext):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    iv = get_random_bytes(16)
    ct = CBC(key, iv, pad(plaintext))
    return iv + ct

def AES_CBC_decrypt_received(key, iv_ct):
    iv = iv_ct[:16]
    ct = iv_ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return unpad(pt_padded)

def RSA_1(n_length):

    if n_length > 2048:
        raise ValueError("too big")
    
    e = 65537

    while True: # repeat until math.gcd true

        p = number.getPrime(n_length) # 2048 max prime
        q = number.getPrime(n_length) # 2048 max prime

        n = p*q # just n

        phi = (p-1)*(q-1) # phi

        if math.gcd(e, phi) == 1: # checks condition
            break

    d = pow(e, -1, phi)

    public = (e, n)
    private = (d, n)

    return public, private, (p, q)


def RSA_ENCRYPT(m, public):
    e, n = public
    if not (0 <= m < n):
        raise ValueError("out of range")
    return pow(m, e, n)

def RSA_DECRYPT(c, private):
    d, n = private
    return pow(c, d, n)

def SHA256_INT(x):
    xb = x.to_bytes((x.bit_length() + 7)//8 or 1, "big")
    return hashlib.sha256(xb).digest()[:16]

def TASK3_SAFE_TEST():

    public, private, pq = RSA_1(548) # alice sends public and private keys
    e, n = public # public

    while True: # bob chooses x
        x = number.getRandomRange(2, n-1)
        if math.gcd(x, n) == 1:
            break

    y = RSA_ENCRYPT(x, public) # bob encrypts secret number with pub key and sends y

    x_alice = RSA_DECRYPT(y, private) # alice decrypts number with priv key

    k_alice = SHA256_INT(x_alice) # alice decrypts k
    k_bob = SHA256_INT(x) # bob decrypts k

    print(f"Bob k:{k_bob}")
    print(f"Alice k:{k_alice}")
    print(f"y:{y}")

def TASK3_NOT_SAFE_TEST():

    public, private, pq = RSA_1(548) # alice sends public and private keys
    e, n = public # public

    while True: # bob chooses s
        s_bob = number.getRandomRange(2, n-1)
        if math.gcd(s_bob, n) == 1:
            break

    c = RSA_ENCRYPT(s_bob, public) # bob encrypts secret number with pub key and sends c

    s_mallory = 1

    c_prime = RSA_ENCRYPT(s_mallory, public)# this is mallory c0, i feel like 1^emodx will always equal 1

    s_alice = RSA_DECRYPT(c_prime, private) # alice computes s with c'
    k_alice = SHA256_INT(s_alice) # alice decrypts k

    k_mallory = SHA256_INT(s_mallory) # mallory tries to find k

    iv_ct = AES_CBC_encrypt_sendable(k_alice, b"hi bob") # returns IV, CT this is what alice sends

    mallory_message = AES_CBC_decrypt_received(k_mallory,iv_ct) # shes able to decrypt bc she has key

    print(f"This is the message mallory got:{mallory_message}")




if __name__ == "__main__":
    TASK3_NOT_SAFE_TEST()
