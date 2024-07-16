"""
RSA keys are used primarily for digital signatures.
This ensures that the encrypted SALSA20 key (which is encrypted using ECC El-Gamal) is indeed from the claimed sender
and hasn't been tampered with during transmission.
This adds an extra layer of security and authenticity to your secure file exchange system.
"""
import hashlib
import random

from elgamal_key_exchange import mod_inverse

"""
Miller-Rabin primality test, a probabilistic algorithm used to determine whether a given number is prime.
"""
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

"""
simple function that will generate a prime number based on number of bits
"""
def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p


"""
Generates a public and a private keys which together satisfy the modular equation
e * d = 1 mod (phi(n))
where public key is (n,e) and private key is (n,d)
"""
def generate_rsa_keypair(bits=2048):
    # Since n = p * q, and p and q are roughly the same size, each prime should be about half the bit length of n.
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (n, e), (n, d)


"""
Create a digital signature for a message using the RSA private key.
"""
def rsa_sign(private_key, message):
    n, d = private_key

    # Hash the message using SHA-1 - we get the MD1 (Message Digest)
    # hash function has many benefits like fix sized, improved security, but it is not mandatory
    hash_object = hashlib.sha1(message)
    hashed_message = hash_object.digest()

    # Convert the hashed message from bytes to an integer - so we could do math
    message_int = int.from_bytes(hashed_message, 'big')

    # Compute the signature as message^d mod n (pow does modulo when provided with 3 params) - this is the encryption
    signature = pow(message_int, d, n)

    # Return the signature as bytes (playing with the numbers to make sure there is no overflow)
    return signature.to_bytes((signature.bit_length() + 7) // 8, 'big')


"""
Verify an RSA signature using the public key.
"""
def rsa_verify(public_key, message, signature):
    n, e = public_key

    # Hash the message using SHA-1 - same as in the signing, the receiver want's the same MD
    hash_object = hashlib.sha1(message)
    hashed_message = hash_object.digest()

    # Convert the hashed message and signature to integers
    message_int = int.from_bytes(hashed_message, 'big')
    signature_int = int.from_bytes(signature, 'big')

    # Compute signature^e mod n - this is the decryption part
    decrypted = pow(signature_int, e, n)

    # Check if the result matches the hashed message, if the private key which the sender used, and the publickey
    # which the receiver uses match then using the SHA1 on the same message will result it
    return decrypted == message_int
