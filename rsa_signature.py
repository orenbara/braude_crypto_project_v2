"""
RSA keys are used primarily for digital signatures.
This ensures that the encrypted SALSA20 key (which is encrypted using ECC El-Gamal) is indeed from the claimed sender
and hasn't been tampered with during transmission.
This adds an extra layer of security and authenticity to your secure file exchange system.
"""
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

    # Converts the message to an integer, In big-endian order,
    # the most significant byte is at the beginning of the byte array.
    # This conversion is necessary because RSA operations are defined on integers modulo n.
    # By converting the message to an integer, we can apply the RSA math (m^d mod n) for signing.
    message_int = int.from_bytes(message, 'big')

    ### Computes the signature as message^d mod n ###
    signature = pow(message_int, d, n)

    ### Returns the signature as bytes ###
    # Why add 7 before dividing? This is a trick to round up to the nearest byte.
    # If we didn't add 7, we might not allocate enough bytes for signatures that aren't exactly divisible by 8 bits.
    return signature.to_bytes((signature.bit_length() + 7) // 8, 'big')


"""
Verify an RSA signature using the public key.
"""
def rsa_verify(public_key, message, signature):
    n, e = public_key
    # Convert the message and signature to integers.
    message_int = int.from_bytes(message, 'big')
    signature_int = int.from_bytes(signature, 'big')

    # Computes signature^e mod n.
    # Python's pow() function with three arguments is optimized for modular exponentiation.
    decrypted = pow(signature_int, e, n)

    # Checks if the result matches the original message.
    return decrypted == message_int
