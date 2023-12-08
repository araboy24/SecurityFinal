import socket
import threading

HOST = '127.0.0.1'
PORT = 8888 # Port that server and clients connect to
active_clients = [] # List of connected users

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
            send_message_to_all("SERVER: "+username+" added to the chat")
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
