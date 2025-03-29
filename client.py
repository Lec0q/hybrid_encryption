from ecies import encrypt as ecc_encrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import socket
import json
import binascii

# --------- AES CBC Encryption Function ---------
def aes_cbc_encrypt(plaintext, aes_key):
    # [Client] Generate a random 16-byte IV for AES encryption
    print("[Client] Generating random 16-byte IV for AES encryption...")
    iv = get_random_bytes(16)
    print("[Client] Generated IV (hex):", iv.hex())
    # [Client] Create AES cipher object for encryption in CBC mode with the generated IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    print("[Client] Padding file data and encrypting using AES CBC mode...")
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Return IV concatenated with ciphertext (to be used for decryption)
    return iv + ciphertext

# --------- TCP Client Setup ---------
HOST = '127.0.0.1'  # Change to server's IP if running on a different machine
PORT = 65432

# Read the file to be transferred (in binary mode)
input_filename = "file_to_send.txt"
print(f"=== Client: Reading file '{input_filename}' to send ===")
with open(input_filename, "rb") as f:
    file_data = f.read()
print(f"[Client] Read {len(file_data)} bytes from '{input_filename}'.")

print("\n=== Client: Step 1 - Connecting to Server ===")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"[Client] Connected to server at {HOST}:{PORT}")

    # Step 2: Receive ECC public key from server
    print("\n[Client] Step 2 - Receiving ECC public key from server...")
    ecc_pub = s.recv(4096).decode()
    print("[Client] Received ECC Public Key (hex):")
    print(ecc_pub)

    # Step 3: Generate a random AES key (16 bytes)
    print("\n[Client] Step 3 - Generating random AES key (16 bytes)...")
    aes_key = get_random_bytes(16)
    print("[Client] Generated AES Key (hex):", aes_key.hex())

    # Step 4: Encrypt AES key using server's ECC public key (ECIES)
    print("\n[Client] Step 4 - Encrypting AES key using server's ECC public key...")
    encrypted_aes_key = ecc_encrypt(ecc_pub, aes_key)
    print("[Client] Encrypted AES Key (hex):", binascii.hexlify(encrypted_aes_key).decode())

    # Step 5: Encrypt file data using AES in CBC mode with the generated AES key
    print("\n[Client] Step 5 - Encrypting file data using AES CBC mode...")
    encrypted_file = aes_cbc_encrypt(file_data, aes_key)
    print("[Client] Encrypted File Data (IV + ciphertext, hex):", binascii.hexlify(encrypted_file).decode())

    # Step 6: Package the encrypted AES key and encrypted file data into JSON (hex-encoded)
    print("\n[Client] Step 6 - Packaging encrypted data into JSON format...")
    data = {
        "encrypted_aes_key": binascii.hexlify(encrypted_aes_key).decode(),
        "encrypted_file": binascii.hexlify(encrypted_file).decode()
    }
    print("[Client] JSON Data to send:", data)

    # Step 7: Send the JSON data to the server over TCP connection
    print("[Client] Step 7 - Sending encrypted data to the server...")
    s.sendall(json.dumps(data).encode())
    print("[Client] Encrypted data sent successfully.")
