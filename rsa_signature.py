import random

from elgamal_key_exchange import mod_inverse


def is_prime(n, k=5):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p

def generate_rsa_keypair(bits=2048):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (n, e), (n, d)

def rsa_sign(private_key, message):
    n, d = private_key
    message_int = int.from_bytes(message, 'big')
    signature = pow(message_int, d, n)
    return signature.to_bytes((signature.bit_length() + 7) // 8, 'big')

def rsa_verify(public_key, message, signature):
    n, e = public_key
    message_int = int.from_bytes(message, 'big')
    signature_int = int.from_bytes(signature, 'big')
    decrypted = pow(signature_int, e, n)
    return decrypted == message_int