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


pwd = '1qaz2wsx'  # the password piece can be edited to be encrypted when sent and the server will decrypt it
alice_key = get_shared_key(pwd)
alice_sent_message1 = 'Hello Bob!'
alice_sent_message2 = 'Hello Bob!'
ciphertext1 = alice_key.encrypt(alice_sent_message1.encode())
ciphertext2 = alice_key.encrypt(alice_sent_message2.encode())
print(ciphertext1)
print(ciphertext2)

bob_key = get_shared_key(pwd)
bob_rec_message1 = ciphertext1
bob_rec_message2 = ciphertext2
plaintext1 = bob_key.decrypt(bob_rec_message1)
print(bob_rec_message1)
print(plaintext1.decode())
plaintext2 = bob_key.decrypt(bob_rec_message2)
print(bob_rec_message2)
print(plaintext2.decode())
