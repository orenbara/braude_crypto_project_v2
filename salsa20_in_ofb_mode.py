import struct
import os

# Constants for SALSA20
ROUNDS = 20


def rotl32(v, c):
    return ((v << c) & 0xffffffff) | (v >> (32 - c))


def quarter_round(a, b, c, d):
    b ^= rotl32(a + d, 7)
    c ^= rotl32(b + a, 9)
    d ^= rotl32(c + b, 13)
    a ^= rotl32(d + c, 18)
    return a, b, c, d


def salsa20_block(input_block):
    # Pad the input to 64 bytes if necessary
    input_block = input_block.ljust(64, b'\x00')

    # convert the 64-byte input block into a list of sixteen 32-bit integers
    x = list(struct.unpack('<16I', input_block))
    orig_x = x[:]

    for _ in range(ROUNDS):
        # Column rounds
        x[0], x[4], x[8], x[12] = quarter_round(x[0], x[4], x[8], x[12])
        x[5], x[9], x[13], x[1] = quarter_round(x[5], x[9], x[13], x[1])
        x[10], x[14], x[2], x[6] = quarter_round(x[10], x[14], x[2], x[6])
        x[15], x[3], x[7], x[11] = quarter_round(x[15], x[3], x[7], x[11])

        # Diagonal rounds
        x[0], x[1], x[2], x[3] = quarter_round(x[0], x[1], x[2], x[3])
        x[5], x[6], x[7], x[4] = quarter_round(x[5], x[6], x[7], x[4])
        x[10], x[11], x[8], x[9] = quarter_round(x[10], x[11], x[8], x[9])
        x[15], x[12], x[13], x[14] = quarter_round(x[15], x[12], x[13], x[14])

    # Adding the original input to the transformed block at the end of salsa20_block ensures that the algorithm is
    # reversible (i.e., it can be decrypted)
    for i in range(16):
        x[i] = (x[i] + orig_x[i]) & 0xffffffff

    return struct.pack('<16I', *x)


def salsa20_encrypt(key, nonce, plaintext):
    if len(key) != 32 or len(nonce) != 8:
        raise ValueError("Key must be 32 bytes and nonce must be 8 bytes")

    keystream = b''
    counter = 0
    while len(keystream) < len(plaintext):
        # Converts the integer counter into an 8-byte binary string (in little-endian format)
        counter_bytes = struct.pack('<Q', counter)

        block = key[:16] + nonce + counter_bytes + key[16:]
        keystream += salsa20_block(block)
        counter += 1
    # XORs the plaintext with the keystream to produce the ciphertext
    return bytes(a ^ b for a, b in zip(plaintext, keystream))


def salsa20_decrypt(key, nonce, ciphertext):
    return salsa20_encrypt(key, nonce, ciphertext)  # Encryption and decryption are the same in OFB mode


# OFB mode implementation
def ofb_mode_encrypt(key, iv, plaintext):
    block_size = 64
    # Splits the plaintext into blocks of block_size
    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]
    ciphertext = b''
    previous_block = iv

    for block in blocks:
        keystream = salsa20_encrypt(key, previous_block[:8], b'\x00' * block_size)[:len(block)]
        cipher_block = bytes(a ^ b for a, b in zip(block, keystream))
        ciphertext += cipher_block
        previous_block = keystream[:8]  # Use the first 8 bytes as the next IV

    return ciphertext


def ofb_mode_decrypt(key, iv, ciphertext):
    return ofb_mode_encrypt(key, iv, ciphertext)  # Decryption is the same as encryption in OFB mode


# File encryption and decryption functions
def encrypt_file(input_file, output_file, key):
    iv = os.urandom(8)
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        plaintext = f_in.read()
        ciphertext = ofb_mode_encrypt(key, iv, plaintext)
        f_out.write(iv + ciphertext)


def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        iv = f_in.read(8)
        ciphertext = f_in.read()
        plaintext = ofb_mode_decrypt(key, iv, ciphertext)
        f_out.write(plaintext)