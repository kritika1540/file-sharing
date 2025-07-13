import socket
import rsa
import os

# Load server's public key
with open("client/rsa_keys/server_public.pem", "rb") as pub_file:
    public_key = rsa.PublicKey.load_pkcs1(pub_file.read())

server_ip = input("Enter Server IP: ")
port = 9999

filename = input("Enter filename to send: ")

with open(filename, "rb") as file:
    file_data = file.read()

# Encrypt
try:
    encrypted_data = rsa.encrypt(file_data, public_key)
except OverflowError:
    print("[-] File too large for RSA encryption (2048-bit can encrypt ~245 bytes only).")
    exit(1)

# Send
client = socket.socket()
client.connect((server_ip, port))

client.send(os.path.basename(filename).encode())  # Send only the file name, not the full path
client.recv(1024)  # ACK

client.sendall(encrypted_data)
print("[✓] Encrypted file sent.")
client.close()