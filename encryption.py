from cryptography.fernet import Fernet

# Generate a key ONCE and save it securely.
# For testing, you can use this hardcoded key:
key = b'K_S0t2NBkAGUl4uFrn2PZq-pLvmVZ_ytqu88B48DB88='

f = Fernet(key)

def encrypt_data(data):
    return f.encrypt(data.encode())

def decrypt_data(token):
    return f.decrypt(token).decode()

