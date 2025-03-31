from ecies.utils import generate_eth_key
from ecies import decrypt as ecc_decrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import socket
import json

# --------- Chức năng tạo khóa ECC ---------
def ecc_priv_key_gen():
    # [Server] Tạo khóa riêng ECC (đối tượng khóa ECC)
    print("[Server] Generating ECC private key...")
    priv_key = generate_eth_key()
    # [Server] In khóa riêng ECC theo định dạng hex
    print("[Server] ECC Private Key (hex):")
    print(priv_key.to_hex())
    return priv_key

def ecc_pub_key_gen(ecc_priv_key):
    # [Server] Sinh khóa công khai ECC từ khóa riêng
    print("[Server] Deriving ECC public key from the private key...")
    pub_key = ecc_priv_key.public_key.to_hex()  # Chuyển đổi khóa công khai sang chuỗi hex
    # [Server] In khóa công khai ECC theo định dạng hex
    print("[Server] ECC Public Key (hex):")
    print(pub_key)
    return pub_key

# --------- Chức năng giải mã AES CBC ---------
def aes_cbc_decrypt(aes_cipher_text, aes_key):
    # [Server] Trích xuất IV từ ciphertext của AES (16 byte đầu tiên)
    print("[Server] Extracting IV from AES ciphertext...")
    iv = aes_cipher_text[:16]
    print("[Server] Extracted IV (hex):", iv.hex())
    # [Server] Tạo đối tượng cipher AES để giải mã bằng cách sử dụng IV đã trích xuất
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # [Server] Giải mã ciphertext (loại trừ IV)
    print("[Server] Decrypting ciphertext (excluding IV)...")
    plaintext_padded = cipher.decrypt(aes_cipher_text[16:])
    # [Server] Loại bỏ padding khỏi dữ liệu tệp đã giải mã
    print("[Server] Removing padding from decrypted file data...")
    plaintext = unpad(plaintext_padded, AES.block_size)
    return plaintext

# --------- Thiết lập máy chủ TCP ---------
HOST = '0.0.0.0'   # Lắng nghe trên tất cả các giao diện mạng
PORT = 65432       # Cổng không cần quyền đặc biệt

print("=== Server: Step 1 - ECC Key Generation ===")
ecc_priv = ecc_priv_key_gen()      # Tạo khóa riêng ECC
ecc_pub = ecc_pub_key_gen(ecc_priv)  # Tạo khóa công khai ECC

print("\n=== Server: Step 2 - Starting TCP Server ===")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Server] Listening on {HOST}:{PORT} ...")
    
    # Bước 3: Chấp nhận kết nối từ client
    conn, addr = s.accept()
    with conn:
        print(f"\n[Server] Step 3 - Connection established with {addr}")
        
        # Bước 4: Gửi khóa công khai ECC cho client
        print("[Server] Step 4 - Sending ECC public key to client...")
        conn.sendall(ecc_pub.encode())
        
        # Bước 5: Nhận dữ liệu được mã hóa (JSON) từ client
        print("\n[Server] Step 5 - Waiting to receive encrypted file data from client...")
        data = conn.recv(4096)
        if not data:
            print("[Server] Error: No data received from client.")
        else:
            # Phân tích dữ liệu JSON thành dictionary
            received = json.loads(data.decode())
            encrypted_aes_key_hex = received["encrypted_aes_key"]
            encrypted_file_hex = received["encrypted_file"]
            print("[Server] Received encrypted data from client:")
            print("  Encrypted AES Key (hex):", encrypted_aes_key_hex)
            print("  Encrypted File Data (hex):", encrypted_file_hex)

            # Chuyển đổi chuỗi hex thành bytes
            encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
            encrypted_file = bytes.fromhex(encrypted_file_hex)
            print("[Server] Converted AES key and file data from hex to bytes.")

            # Ghi một bản sao của dữ liệu tệp được mã hóa xuống đĩa
            encrypted_filename = "encrypted_file_copy.bin"
            with open(encrypted_filename, "wb") as f_enc:
                f_enc.write(encrypted_file)
            print(f"[Server] Encrypted file copy saved as '{encrypted_filename}'.")

            # Bước 6: Giải mã khóa AES bằng cách sử dụng khóa riêng ECC
            print("\n[Server] Step 6 - Decrypting AES key using ECC private key...")
            aes_key = ecc_decrypt(ecc_priv.to_hex(), encrypted_aes_key)
            print("[Server] Decrypted AES Key (hex):", aes_key.hex())

            # Bước 7: Giải mã dữ liệu tệp được mã hóa bằng AES-CBC sử dụng khóa AES đã được giải mã
            print("\n[Server] Step 7 - Decrypting AES-CBC encrypted file data...")
            file_data = aes_cbc_decrypt(encrypted_file, aes_key)
            
            # Bước 8: Ghi dữ liệu tệp đã giải mã xuống đĩa và in nội dung của nó
            output_filename = "received_file.txt"
            with open(output_filename, "wb") as f_out:
                f_out.write(file_data)
            print(f"\n[Server] Step 8 - Decryption complete. Decrypted file saved as '{output_filename}'.")
            print("\n[Server] Decrypted file content:")
            try:
                # Giả định tệp chứa văn bản
                print(file_data.decode())
            except UnicodeDecodeError:
                print("[Server] Decrypted file is not valid text data.")
