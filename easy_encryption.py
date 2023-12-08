import base64
import random
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


# a function to generate a properly formatted key using SHA256, given a password
def generate_key(password):
    random.seed(password)  # same password = same "random" number = same key
    salt = random.randbytes(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32
    )
    shared_key = kdf.derive(password.encode())
    f = Fernet(base64.urlsafe_b64encode(shared_key))
    return f


pwd = '1qaz2wsx'
alice_key = generate_key(pwd)
alice_message = 'Hello Bob!'
ciphertext = alice_key.encrypt(alice_message.encode())
print(alice_message)
print(ciphertext)

bob_key = generate_key(pwd)
received_ciphertext = ciphertext
received_plaintext = bob_key.decrypt(received_ciphertext)
print(received_ciphertext)
print(received_plaintext.decode())

