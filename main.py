import tkinter as tk
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

# GUI setup
def send_message():
    message = entry.get()
    encrypted_msg = encrypt_message(shared_key, message)
    # Display encrypted message in GUI
    # You can send this encrypted_msg over the network

def receive_message():
    # Simulating receiving an encrypted message from the network
    encrypted_message = b'...'  # Replace with the received encrypted message
    decrypted_msg = decrypt_message(shared_key, encrypted_message)
    # Display decrypted message in GUI

# Replace 'passphrase' with the shared password between Alice and Bob
passphrase = "sharedpassword"
shared_key = generate_key(passphrase)

# GUI initialization
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

receive_button = tk.Button(frame, text="Receive", command=receive_message)
receive_button.pack()

root.mainloop()
