import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import messagebox

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


def listen_for_messages(client):
    while True:
        message = client.recv(2048).decode('utf-8')
        if message != '':
            username = message.split(': ')[0]
            content = message.split(': ')[1]
            add_message(f"[{username}] {content}")
        else:
            messagebox.showerror("Invalid Message", "Received an empty message")


def communicate_to_server(client):
    username = username_textbox.get()
    if username != '':
        client.sendall(username.encode())
    else:
        messagebox.showerror("Invalid username", "Username cannot be empty")

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
        client.sendall(message.encode())
        message_textbox.delete(0, len(message))
    else:
        messagebox.showerror("Invalid Message", "Message cannot be empty")


# Creates the clients GUI
root = tk.Tk()
root.geometry("600x600")  # Specifying window size
root.title("Super Secure Chat")
root.resizable(False, False)  # Locking window size

root.grid_rowconfigure(0, weight=1)
root.grid_rowconfigure(1, weight=4)
root.grid_rowconfigure(2, weight=1)

top_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)
middle_frame = tk.Frame(root, width=600, height=400)
bottom_frame = tk.Frame(root, width=600, height=100, bg=DARK_GREY)

top_frame.grid(row=0, column=0, sticky=tk.NSEW)
middle_frame.grid(row=1, column=0, sticky=tk.NSEW)
bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

username_label = tk.Label(top_frame, text="Enter username:", font=LARGE_FONT, bg=DARK_GREY, fg=WHITE)
username_label.pack(side=tk.LEFT, padx=10)

username_textbox = tk.Entry(top_frame, font=LARGE_FONT, bg=DARK_BLUE, fg=WHITE, width=20)
username_textbox.pack(side=tk.LEFT)

username_button = tk.Button(top_frame, text="Join", font=LARGE_FONT, bg=BLUE, fg=WHITE, command=connect)
username_button.pack(side=tk.LEFT, padx=15)

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
