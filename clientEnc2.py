import base64
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

from cryptography.fernet import Fernet

import server

DARK_GREY = '#212121'
DARK_BLUE = '#161e2e'
BLUE = '#4a7ce0'
WHITE = 'white'
LARGE_FONT = ("Arial Baltic", 17)
BUTTON_FONT = ("Arial Baltic", 15)
SMALL_FONT = ("Arial Baltic", 13)

HOST = '127.0.0.1'
PORT = 8888

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# a random key is generated then XOR'd with the password to generate a new shared key
# key1 = server.get_key()
client_key = None


# def get_shared_key(password):
#     pwd_bytes = password.encode()  # changing pw string to bytes to perform bitwise operations
#     padded_pwd = pwd_bytes.ljust(32, b'0')  # considering padding using random bytes but this is fine for now.
#     shared_key = bytes(key1 ^ padded_pwd for key1, padded_pwd in zip(key1, padded_pwd))  # XOR
#     shared_key = Fernet(base64.urlsafe_b64encode(shared_key))
#     print('shared key:',shared_key)
#     return shared_key


def listen_for_messages(client):
    while True:
        # try:
        message = client.recv(2048).decode('utf-8')
        if message:
            print(message)
            username, content = message.split(': ', 1)
            if client_key:
                # try:
                plaintext = client_key.decrypt(content.encode()).decode()
                print(plaintext)
                add_message(f"[{username}] {plaintext}")
                # except Exception as e:
                #     print("Decryption error:", e)
            # else:
            #     add_message(f"[{username}] {content}")  # If no client_key is set, show the message as is
        else:
            messagebox.showerror("Invalid Message", "Received an empty message")
        # except Exception as e:
        #     print("Error receiving message:", e)
        #     break  # Break the loop on receiving errors

# def listen_for_messages(client):
#     while True:
#         message = client.recv(2048).decode('utf-8')
#         if message != '':
#             print(message)
#             # message = client_key.decrypt(message)
#             username = message.split(': ')[0]
#             content = message.split(': ')[1]
#             print(client_key)
#             plaintext = str(client_key.decrypt(content))
#             add_message(f"[{username}] {plaintext}")
#         else:
#             messagebox.showerror("Invalid Message", "Received an empty message")


def communicate_to_server(client):
    global client_key
    username = username_textbox.get()
    password = password_textbox.get()
    if username != '' and password != '':
        client_key = server.get_shared_key(password)
        print('client_key', client_key)
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid", "Username and password cannot be empty")

    threading.Thread(target=listen_for_messages, args=(client,)).start()


def add_message(message):
    message_box.config(state=tk.NORMAL)
    message_box.insert(tk.END, message + '\n')
    message_box.config(state=tk.DISABLED)


def connect():
    try:
        # Connecting client to server
        client.connect((HOST, PORT))
        add_message("[SERVER] Successfully connected to server")
    except Exception as e:
        messagebox.showerror("Unable to connect to server", e)

    communicate_to_server(client)
    username_textbox.config(state=tk.DISABLED)
    username_button.config(state=tk.DISABLED)


def send_message():
    message = message_textbox.get()
    if message != '':
        try:
            ciphertext = client_key.encrypt(message.encode())
            client.sendall(ciphertext)
            message_textbox.delete(0, len(message))
        except Exception as e:
            messagebox.showerror("Error", "Did you enter your password?")
            print(e)
        # client.sendall(message.encode())
        # message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Invalid Message", "Message cannot be empty")


# Creates the clients GUI
root = tk.Tk()
root.geometry("600x630")  # Specifying window size
root.title("Super Secure Chat")
root.resizable(False, False)  # Locking window size

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=1)
root.grid_rowconfigure(2, weight=4)
root.grid_rowconfigure(3, weight=1)

top_frame_username = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
top_frame_password = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
middle_frame = tk.Frame(root, width=600, height=400)
bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)

top_frame_username.grid(row=0, column=0, sticky=tk.NSEW)
top_frame_password.grid(row=1, column=0, sticky=tk.NSEW)
middle_frame.grid(row=2, column=0, sticky=tk.NSEW)
bottom_frame.grid(row=3, column=0, sticky=tk.NSEW)

username_label = tk.Label(top_frame_username, text="Enter username:", font=LARGE_FONT, bg=DARK_GREY, fg=WHITE)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(top_frame_username, font=LARGE_FONT, bg=DARK_BLUE, fg=WHITE, width=20)
username_textbox.pack(side=tk.LEFT)

password_label = tk.Label(top_frame_password, text="Enter password:", font=LARGE_FONT, bg=DARK_GREY, fg=WHITE)
password_label.pack(side=tk.LEFT, padx=10)

password_textbox = tk.Entry(top_frame_password, font=LARGE_FONT, bg=DARK_BLUE, fg=WHITE, width=20)
password_textbox.pack(side=tk.LEFT)

username_button = tk.Button(top_frame_password, text="Join", font=LARGE_FONT, bg=BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=15)
#
# password_button = tk.Button(top_frame_password, text="Get Key", font=LARGE_FONT, bg=BLUE, fg=WHITE, command=connect)
# password_button.pack(side=tk.LEFT, padx=15)

message_textbox = tk.Entry(bottom_frame, font=LARGE_FONT, bg=DARK_BLUE, fg=WHITE, width=38)
message_textbox.pack(side=tk.LEFT, padx=10)

message_button = tk.Button(bottom_frame, text="Send", font=BUTTON_FONT, bg=BLUE, fg=WHITE, command=send_message)
message_button.pack(side=tk.LEFT, padx=10)

message_box = scrolledtext.ScrolledText(middle_frame, font=SMALL_FONT, bg=DARK_BLUE, fg=WHITE, width=67, height=26.5)
message_box.config(state=tk.DISABLED)
message_box.pack(side=tk.TOP)

def main():
    root.mainloop()
    communicate_to_server(client)


if __name__ == '__main__':
    main()
