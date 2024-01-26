import random

def generate_keypair(p, g):
    private_key = random.randint(1, p - 1)
    public_key = (g ** private_key) % p
    return private_key, public_key

def calculate_shared_secret(private_key, other_public_key, p):
    return (other_public_key ** private_key) % p
