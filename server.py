from ecies.utils import generate_eth_key
from ecies import decrypt as ecc_decrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import socket
import json

# --------- ECC Key Generation Functions ---------
def ecc_priv_key_gen():
    # [Server] Generate ECC private key (ECC key object)
    print("[Server] Generating ECC private key...")
    priv_key = generate_eth_key()
    # [Server] Print ECC private key in hex format
    print("[Server] ECC Private Key (hex):")
    print(priv_key.to_hex())
    return priv_key

def ecc_pub_key_gen(ecc_priv_key):
    # [Server] Derive ECC public key from the private key
    print("[Server] Deriving ECC public key from the private key...")
    pub_key = ecc_priv_key.public_key.to_hex()  # Convert public key to hex string
    # [Server] Print ECC public key in hex format
    print("[Server] ECC Public Key (hex):")
    print(pub_key)
    return pub_key

# --------- AES CBC Decryption Function ---------
def aes_cbc_decrypt(aes_cipher_text, aes_key):
    # [Server] Extract IV from AES ciphertext (first 16 bytes)
    print("[Server] Extracting IV from AES ciphertext...")
    iv = aes_cipher_text[:16]
    print("[Server] Extracted IV (hex):", iv.hex())
    # [Server] Create AES cipher object for decryption using the extracted IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # [Server] Decrypt the ciphertext (excluding the IV)
    print("[Server] Decrypting ciphertext (excluding IV)...")
    plaintext_padded = cipher.decrypt(aes_cipher_text[16:])
    # [Server] Remove padding from decrypted file data
    print("[Server] Removing padding from decrypted file data...")
    plaintext = unpad(plaintext_padded, AES.block_size)
    return plaintext

# --------- TCP Server Setup ---------
HOST = '0.0.0.0'   # Listen on all network interfaces
PORT = 65432       # Non-privileged port

print("=== Server: Step 1 - ECC Key Generation ===")
ecc_priv = ecc_priv_key_gen()      # Generate ECC private key
ecc_pub = ecc_pub_key_gen(ecc_priv)  # Generate ECC public key

print("\n=== Server: Step 2 - Starting TCP Server ===")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Server] Listening on {HOST}:{PORT} ...")
    
    # Step 3: Accept connection from client
    conn, addr = s.accept()
    with conn:
        print(f"\n[Server] Step 3 - Connection established with {addr}")
        
        # Step 4: Send ECC public key to the client
        print("[Server] Step 4 - Sending ECC public key to client...")
        conn.sendall(ecc_pub.encode())
        
        # Step 5: Receive encrypted data (JSON) from client
        print("\n[Server] Step 5 - Waiting to receive encrypted file data from client...")
        data = conn.recv(4096)
        if not data:
            print("[Server] Error: No data received from client.")
        else:
            # Parse JSON data into a dictionary
            received = json.loads(data.decode())
            encrypted_aes_key_hex = received["encrypted_aes_key"]
            encrypted_file_hex = received["encrypted_file"]
            print("[Server] Received encrypted data from client:")
            print("  Encrypted AES Key (hex):", encrypted_aes_key_hex)
            print("  Encrypted File Data (hex):", encrypted_file_hex)

            # Convert hex strings to bytes
            encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
            encrypted_file = bytes.fromhex(encrypted_file_hex)
            print("[Server] Converted AES key and file data from hex to bytes.")

            # Write a copy of the encrypted file data to disk
            encrypted_filename = "encrypted_file_copy.bin"
            with open(encrypted_filename, "wb") as f_enc:
                f_enc.write(encrypted_file)
            print(f"[Server] Encrypted file copy saved as '{encrypted_filename}'.")

            # Step 6: Decrypt AES key using ECC private key
            print("\n[Server] Step 6 - Decrypting AES key using ECC private key...")
            aes_key = ecc_decrypt(ecc_priv.to_hex(), encrypted_aes_key)
            print("[Server] Decrypted AES Key (hex):", aes_key.hex())

            # Step 7: Decrypt AES-CBC encrypted file data using the decrypted AES key
            print("\n[Server] Step 7 - Decrypting AES-CBC encrypted file data...")
            file_data = aes_cbc_decrypt(encrypted_file, aes_key)
            
            # Step 8: Write the decrypted file data to disk and print its content
            output_filename = "received_file.txt"
            with open(output_filename, "wb") as f_out:
                f_out.write(file_data)
            print(f"\n[Server] Step 8 - Decryption complete. Decrypted file saved as '{output_filename}'.")
            print("\n[Server] Decrypted file content:")
            try:
                # Assume the file contains text
                print(file_data.decode())
            except UnicodeDecodeError:
                print("[Server] Decrypted file is not valid text data.")
