import socket
import threading
import hashlib
import random
import json
import time
import diffieHellman
from Encryption import Encryption
from SmartHome import TempController
import DiskEncryption


p = 23
g = 5

private_server_key, server_public_key = diffieHellman.generate_keypair(p, g)


def start_server():
    #dummy server configuration

    

    host = 'localhost'
    port = 12345

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(5) # listens for connection for 5 seconds...

    #server status
    print("Server started.")
    print("Server listening on port", port)

    #initialize temp controller
    tempNode = TempController()
    inputString = "Derby"
    baseEncryption = hashlib.sha256(inputString.encode())
    digested = baseEncryption.hexdigest()
    cipher = Encryption(digested)
    

    while True:
        conn, address = server_socket.accept()

        

        # diffie hellman key exchange
        conn_public_key = diffieHellman.exchange_public_key(conn, server_public_key)
        shared_key = diffieHellman.generate_shared_key(p, g, private_server_key)

        #cipher = Encryption(str(shared_key))

        client_thread = threading.Thread(target=handle_client, args=(conn, address, tempNode, cipher))
        client_thread.start()

def create_user(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest() # simple sha256 hashing on for level 1 security

    try:
        with open('accounts.json', 'r+') as file:
            try:
                users = json.load(file)
            except json.JSONDecodeError:
                users = {}
            if username in users:
                return False 
            users[username] = hashed_password 
            file.seek(0)
            json.dump(users, file)

    except FileNotFoundError: # adds new use users.json file if it doesnt exist
        with open('accounts.json', 'w') as file:
            users = {username: hashed_password}
            json.dump(users, file)
    return True

def login_user(username, password):

    hashed_password = hashlib.sha256(password.encode()).hexdigest() #hexidigest() converts to hexidecimal string
    with open('accounts.json', 'r') as file:
        users = json.load(file)
        if username in users and users[username] == hashed_password: #checks if user and password is corrrect 
            return True  # Login successful
    return False

MAX_LOGIN_ATTEMPTS  = 3

def handle_client(conn, address, tempNode, cipher):

    print(f"Connection from: {address} Connected.") 
    user_logged_in = False
    login_attempts = 0
    penalty_duration = 10

    while True:
        encrypted_data = conn.recv(1024).decode()
        if not encrypted_data: 
            break

        decrypted_data = cipher.decrypt(encrypted_data)
        print(f"Encrypted message from {address}: {encrypted_data}")

        if decrypted_data.startswith("REGISTER"): 
            _, username, password = decrypted_data.split()
            success = create_user(username, password)
            response = "Registration successful" if success else "Registration failed"
        elif decrypted_data.startswith("LOGIN"):
            _, username, password = decrypted_data.split()

            # Check if the user is in the JSON file
            with open('accounts.json', 'r') as file:
                users = json.load(file)
                if username in users and users[username] == hashlib.sha256(password.encode()).hexdigest():
                    user_logged_in = True
                    login_attempts = 0
                    response = "Login successful"
                else:
                    login_attempts += 1
                    if login_attempts == 3:
                        response = f"Invalid login attempts. Login was locked for {penalty_duration} seconds"
                        time.sleep(penalty_duration)
                        penalty_duration *= 2
                        login_attempts = 0
                    else:
                        response = f"Invalid login attempt {login_attempts}/{MAX_LOGIN_ATTEMPTS}"

        elif user_logged_in:
            # Process temperature control commands
            if decrypted_data == "ON":
                tempNode.set_state("ON")
                response = "Temperature control is now ON"
            elif decrypted_data == "OFF":
                tempNode.set_state("OFF")
                response = "Temperature control is now OFF"
            elif decrypted_data.startswith("TEMP"):
                try:
                    _, temperature = decrypted_data.split()
                    temperature_value = float(temperature)
                    print (temperature_value)
                    if 0 <= temperature_value <= 100:
                        tempNode.set_temp(temperature_value)
                        response = f"Temperature set to {temperature_value}"
                    else:
                        response = "Temperature value must be between 0 and 100"
                except ValueError:
                    response = "Invalid temperature command"
            else:
                response = "Unknown command"
        else:
            response = "Please login or register"

        encrypted_response = cipher.encrypt(response)
        conn.send(encrypted_response.encode())

    conn.close()
    print(f"Connection with {address} closed.")


if __name__ == '__main__':
    start_server()