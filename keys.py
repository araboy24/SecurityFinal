import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def get_shared_key(password):
    # pwd_bytes = password.encode()  # changing pw string to bytes to perform bitwise operations
    padded_pwd = password.ljust(32, b'0')  # considering padding using random bytes but this is fine for now.
    shared_key = bytes(key1 ^ padded_pwd for key1, padded_pwd in zip(key1, padded_pwd))  # XOR
    # shared_key = Fernet(base64.urlsafe_b64encode(shared_key))
    return shared_key


# SERVER generates fernet key
key1 = Fernet.generate_key()

# Generate public and private keys for SERVER and CLIENT
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
server_public_key = server_private_key.public_key()

client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
client_public_key = client_private_key.public_key()

# CLIENT sends the password encrypted with SERVER public key
password = '1qaz2wsx'
print('password: ', password)
encrypted_password = server_public_key.encrypt(
    password.encode('utf-8'),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print('encrypted password: ', encrypted_password)

# SERVER decrypts password using SERVER private key
decrypted_password = server_private_key.decrypt(
    encrypted_password,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print('decrypted password: ', decrypted_password.decode('utf-8'))

# SERVER makes a shared key using password
shared_key = get_shared_key(decrypted_password)
print('shared key: ', shared_key)

# SERVER sends CLIENT shared key encrypted with CLIENT public key
encrypted_shared_key = client_public_key.encrypt(
    shared_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print('encrypted shared key: ', encrypted_shared_key)

# CLIENT decrypts shared key using CLIENT private key
decrypted_shared_key = client_private_key.decrypt(
    encrypted_shared_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print('decrypted shared key: ', decrypted_shared_key)

#  CLIENT turns shared key into fernet key object
shared_key = Fernet(base64.urlsafe_b64encode(shared_key))

# CLIENT can now encrypt/decrypt messages with shared key
message = 'Hello World!'
encrypted_message = shared_key.encrypt(message.encode())
print('encrypted message: ', encrypted_message)
decrypted_message = shared_key.decrypt(encrypted_message).decode()
print('decrypted message: ', decrypted_message)
