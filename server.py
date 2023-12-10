import base64
import socket
import threading

from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 8888 # Port that server and clients connect to
active_clients = [] # List of connected users
stored_passwords = {}

key1 = Fernet.generate_key()
print('key1', key1)

def get_shared_key(password):
    global stored_passwords
    print(stored_passwords)
    if password in stored_passwords.keys():
        print('howdy')
        return stored_passwords[password]
    pwd_bytes = password.encode()  # changing pw string to bytes to perform bitwise operations
    padded_pwd = pwd_bytes.ljust(32, b'0')  # considering padding using random bytes but this is fine for now.
    shared_key = bytes(key1 ^ padded_pwd for key1, padded_pwd in zip(key1, padded_pwd))  # XOR
    print(shared_key)
    shared_key = Fernet(base64.urlsafe_b64encode(shared_key))
    # print('shared key:',shared_key)
    stored_passwords[password] = shared_key
    return shared_key

def get_key():
    return key1

# Sends message to single client
def send_message_to_client(client, message):
    client.sendall(message.encode())

# Send message to connected clients
def send_message_to_all(message):
    for user in active_clients:
        send_message_to_client(user[1], message)

# Listens for messages from clients
def listen_for_messages(client, username):
    while True:
        message = client.recv(2048).decode('utf-8')
        if message != '':
            final_message = username + ': ' + message
            send_message_to_all(final_message)
        else:
            print("Message was empty")
def client_handler(client):
    # Server will listen for client message that contain username
    while True:
        username = client.recv(2048).decode('utf-8')
        if username != '':
            active_clients.append((username, client))
            # send_message_to_all("SERVER: "+username+" added to the chat")
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
