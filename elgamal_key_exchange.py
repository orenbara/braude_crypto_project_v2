import random

# Elliptic curve parameters (using NIST P-256 curve)
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def mod_inverse(a, m):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % m, m
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % m

def is_on_curve(point):
    if point is None:
        return True
    x, y = point
    return (y * y - x * x * x - a * x - b) % p == 0

def point_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if P1[0] == P2[0] and P1[1] != P2[1]:
        return None
    if P1 == P2:
        lam = (3 * P1[0] * P1[0] + a) * mod_inverse(2 * P1[1], p)
    else:
        lam = (P2[1] - P1[1]) * mod_inverse(P2[0] - P1[0], p)
    x3 = (lam * lam - P1[0] - P2[0]) % p
    y3 = (lam * (P1[0] - x3) - P1[1]) % p
    return (x3, y3)

"""
This uses the double-and-add algorithm, an efficient method for scalar multiplication
Scalar multiplication involves computing the product of a scalar (integer) k and a point P on an elliptic curve 
to obtain another point Q on the curve, denoted as Q=kP This operation is analogous to repeated addition in the 
context of elliptic curves.
"""
def scalar_mult(k, P):
    Q = None
    for i in range(256):
        if k & (1 << i):
            Q = point_add(Q, P)
        P = point_add(P, P)
    return Q


"""
Generate an ECC key pair
"""
def generate_keypair():
    # Chooses a random integer as the private key
    private_key = random.randint(1, n - 1)

    # Computes the public key by multiplying the generator point (Gx, Gy) by the private key.
    public_key = scalar_mult(private_key, (Gx, Gy))
    return private_key, public_key

"""
Encrypt a message (in this case, the SALSA20 key) using ECC El-Gamal encryption
"""
def encrypt_key(public_key, plaintext):
    # Chooses a random k for this encryption.
    k = random.randint(1, n - 1)
    C1 = scalar_mult(k, (Gx, Gy))
    S = scalar_mult(k, public_key)
    C2 = (plaintext * S[0]) % p
    return (C1, C2)

def decrypt_key(private_key, ciphertext):
    C1, C2 = ciphertext
    S = scalar_mult(private_key, C1)
    plaintext = (C2 * mod_inverse(S[0], p)) % p
    return plaintext