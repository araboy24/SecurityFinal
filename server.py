import base64
import socket
import threading

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

HOST = '127.0.0.1'
PORT = 8888 # Port that server and clients connect to
active_clients = [] # List of connected users

key1 = Fernet.generate_key()

# Generate public and private keys for SERVER and CLIENT
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
server_public_key = server_private_key.public_key()

def get_shared_key(password):
    pwd_bytes = password.encode()  # changing pw string to bytes to perform bitwise operations
    padded_pwd = pwd_bytes.ljust(32, b'0')  # considering padding using random bytes but this is fine for now.
    shared_key = bytes(key1 ^ padded_pwd for key1, padded_pwd in zip(key1, padded_pwd))  # XOR
    return shared_key

def get_key():
    return key1

# Sends message to single client
def send_message_to_client(client, message):
    client.sendall(message.encode())

# Send message to connected clients
def send_message_to_all(message, sender_username):
    for user in active_clients:
        if user[0] == sender_username:
            continue
        send_message_to_client(user[1], message)

# Listens for messages from clients
def listen_for_messages(client, username):
    while True:
        message = client.recv(2048).decode('utf-8')

        if message != '':
            final_message = username + ': ' + message
            send_message_to_all(final_message, username)
        else:
            print("Message was empty")

def client_handler(client):
    serialized_public_key = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client.sendall(serialized_public_key)
    # Server will listen for client message that contain username
    while True:
        data = client.recv(2048).decode('utf-8')
        username, encrypted_password_base64, serialized_public_key_from_client = data.split(' ', 2)
        client_public_key = serialization.load_pem_public_key(
            serialized_public_key_from_client.encode(),
            backend=default_backend()
        )
        encrypted_password = base64.b64decode(encrypted_password_base64)
        password = server_private_key.decrypt(
            encrypted_password,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode()

        if username != '':
            active_clients.append((username, client))
            og_server_shared_key = get_shared_key(password)
            enc_server_shared_key = client_public_key.encrypt(
                og_server_shared_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            enc_server_shared_key_base_64 = base64.b64encode(enc_server_shared_key).decode('utf-8')
            client.sendall(enc_server_shared_key_base_64.encode()) # sending string of encrypted shared key to client
            break
        else:
            print("Client username invalid")
    threading.Thread(target=listen_for_messages, args=(client, username)).start()
def main():
    # Creating socket class object
    # AF_INET is for IPv4
    # SOCK_STREAM for TCP Packets
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Giving the server an address
        server.bind((HOST, PORT))
        print(f"Server running on {HOST} Port: {PORT}")
    except Exception as e:
        print("Unable to connect to", HOST, PORT)
        print(e)

    # Setting the max number of clients allowed
    server.listen(2)
    while True:
        client, address = server.accept()
        print("Client successfully connected:", address)

        # Starting a thread for new client
        threading.Thread(target=client_handler, args=(client,)).start()


if __name__ == '__main__':
    main()
