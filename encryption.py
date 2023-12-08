import base64
from cryptography.fernet import Fernet

# Server generates a shared key using the password
# a random key is generated then XOR'd with the password to generate a new shared key
key1 = Fernet.generate_key()


def get_shared_key(password):
    pwd_bytes = password.encode()  # changing pw string to bytes to perform bitwise operations
    padded_pwd = pwd_bytes.ljust(32, b'0')  # considering padding using random bytes but this is fine for now.
    shared_key = bytes(key1 ^ padded_pwd for key1, padded_pwd in zip(key1, padded_pwd))  # XOR
    shared_key = Fernet(base64.urlsafe_b64encode(shared_key))
    return shared_key


pwd = '1qaz2wsx'
alice_key = get_shared_key(pwd)
alice_sent_message = 'Hello Bob!'
ciphertext = alice_key.encrypt(alice_sent_message.encode())
print(ciphertext)

bob_key = get_shared_key(pwd)
bob_rec_message = ciphertext
plaintext = bob_key.decrypt(bob_rec_message)
print(bob_rec_message)
print(plaintext.decode())
