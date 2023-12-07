import tkinter as tk
import socket
from cryptography.fernet import Fernet

# Generate a key from a passphrase (you might want to use a more secure method for real-world scenarios)
def generate_key(passphrase):
    return Fernet.generate_key()

# Encrypt a message using the key
def encrypt_message(key, message):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode())

# Decrypt a message using the key
def decrypt_message(key, encrypted_message):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_message).decode()

def send_message():
    message = entry.get()
    encrypted_msg = encrypt_message(shared_key, message)
    # Send the encrypted message over the network to the other user
    client_socket.send(encrypted_msg)

def receive_message():
    # Receive encrypted message from the other user
    encrypted_message = client_socket.recv(1024)
    decrypted_msg = decrypt_message(shared_key, encrypted_message)
    # Display decrypted message in GUI
    chat_box.insert(tk.END, decrypted_msg + '\n')

def start_client():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 5555))  # Replace with the server's IP and port
    receive_message()

def start_server():
    global client_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 5555))  # Replace with the server's IP and port
    server_socket.listen(1)
    client_socket, addr = server_socket.accept()
    receive_message()

# Replace 'passphrase' with the shared password between Alice and Bob
passphrase = "sharedpassword"
shared_key = generate_key(passphrase)

root = tk.Tk()
root.title("Secure Chat")

frame = tk.Frame(root)
frame.pack()

label = tk.Label(frame, text="Enter Message:")
label.pack()

entry = tk.Entry(frame)
entry.pack()

send_button = tk.Button(frame, text="Send", command=send_message)
send_button.pack()

chat_box = tk.Text(frame)
chat_box.pack()

start_server_button = tk.Button(frame, text="Start Server", command=start_server)
start_server_button.pack()

start_client_button = tk.Button(frame, text="Start Client", command=start_client)
start_client_button.pack()

root.mainloop()
