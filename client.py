import socket
import tkinter as tk
import hashlib
import random
from Encryption import Encryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

import diffieHellman

p = 23
g = 5

private_client_key, client_public_key = diffieHellman.generate_keypair(p, g)


# Define global variables
client_socket = None
client_cipher = None
username_entry = None
password_entry = None
command_entry = None

def send_command(command):
    encrypted_message = client_cipher.encrypt(command)
    client_socket.send(encrypted_message.encode())
    data = client_socket.recv(1024).decode()
    decrypted_data = client_cipher.decrypt(data)
    print("Server response: " + decrypted_data)

def handle_register_login(action):
    username = username_entry.get()
    password = password_entry.get()
    send_command(f"{action} {username} {password}")

def handle_command():
    command = command_entry.get()
    send_command(command)

def start_client():
    global client_socket, client_cipher, username_entry, password_entry, command_entry

    host = 'localhost'
    port = 12345

    try:
        client_socket = socket.socket()
        client_socket.connect((host, port))
    except Exception as e:
        print("Error connecting to the server:", str(e))
        return

    inputString = "random"
    baseEncryption = hashlib.sha256(inputString.encode())
    digested = baseEncryption.hexdigest()

    # diffie hellman key exchange
    private_client_key, client_public_key = diffieHellman.generate_keypair(p, g)
    
    server_public_key = diffieHellman.exchange_public_key(client_socket, client_public_key)
    shared_key = diffieHellman.generate_shared_key(p, g, private_client_key)

    client_cipher = Encryption(str(shared_key))

    root = tk.Tk()
    root.title("Client")

    action_label = tk.Label(root, text="Choose action (REGISTER, LOGIN, COMMAND):")
    action_label.pack()

    action_var = tk.StringVar()
    action_var.set("REGISTER")

    action_option = tk.OptionMenu(root, action_var, "REGISTER", "LOGIN", "COMMAND")
    action_option.pack()

    username_label = tk.Label(root, text="Enter username:")
    username_label.pack()
    username_entry = tk.Entry(root)
    username_entry.pack()

    password_label = tk.Label(root, text="Enter password:")
    password_label.pack()
    password_entry = tk.Entry(root, show="*")
    password_entry.pack()

    command_label = tk.Label(root, text="Enter command (ON, OFF, TEMP [0-100]):")
    command_label.pack()
    command_entry = tk.Entry(root)
    command_entry.pack()

    def handle_register_login_action():
        action = action_var.get()
        username = username_entry.get()
        password = password_entry.get()

        if not username or not password:
            print("Please enter both username and password.")
            return

        send_command(f"{action} {username} {password}")

    register_login_button = tk.Button(root, text="Submit", command=handle_register_login_action)
    register_login_button.pack()

    def handle_command_action():
        command = command_entry.get()

        if not command:
            print("Please enter a command.")
            return

        send_command(command)

    command_button = tk.Button(root, text="Send Command", command=handle_command_action)
    command_button.pack()

    def close_connection():
        client_socket.close()
        root.destroy()

    quit_button = tk.Button(root, text="QUIT", command=close_connection)
    quit_button.pack()

    root.mainloop()



if __name__ == '__main__':
    start_client()


