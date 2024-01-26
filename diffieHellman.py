import random

def generate_keypair(p, g):
    private_key = random.randint(1, p - 1)
    public_key = (g ** private_key) % p
    return private_key, public_key

def calculate_shared_secret(private_key, other_public_key, p):
    return (other_public_key ** private_key) % p


def generate_shared_key(p, g, private_key):
    return (g ** private_key) % p

def exchange_public_key(conn, public_key):
    conn.send(str(public_key).encode())
    received_public_key = int(conn.recv(1024).decode())
    return received_public_key
