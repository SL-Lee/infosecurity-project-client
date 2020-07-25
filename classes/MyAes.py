from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def get_fixed_key():
    # use fixed AES key, 256 bits
    return b"\x89E\xa4\xdeYt\xc6x\xc8^3\xf1\x12\xc3\x04~\xd9\xc3\xfb\x82L\xaaTY\xfb\xc4n\x13\xfd\x80\xeew"
    # return b"%d" % key


def get_random_key():
    """ generate random AES key, keysize = 32*8 = 256 bits"""
    return get_random_bytes(32)


# AES encrypt using CBC and IV, with default padding (PKCS7)
def encrypt(key, plaintext_utf8):
    cipher = AES.new(key, AES.MODE_CBC)     # Q6
    ciphertext = cipher.encrypt(pad(plaintext_utf8, AES.block_size))

    return ciphertext, cipher.iv


# AES decrypt using CBC and IV, with default unpadding (PKCS7)
def decrypt(key,ciphertext, iv):

    cipher = AES.new(key, AES.MODE_CBC, iv)     # Q6
    decryptedtext_utf = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return decryptedtext_utf
