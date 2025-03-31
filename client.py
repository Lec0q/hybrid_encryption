from ecies import encrypt as ecc_encrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import socket
import json
import binascii

# --------- Hàm mã hóa AES CBC ---------
def aes_cbc_encrypt(plaintext, aes_key):
    # [Client] Tạo IV ngẫu nhiên 16-byte cho mã hóa AES
    print("[Client] Generating random 16-byte IV for AES encryption...")
    iv = get_random_bytes(16)
    print("[Client] Generated IV (hex):", iv.hex())
    # [Client] Tạo đối tượng cipher AES để mã hóa ở chế độ CBC với IV đã tạo
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    print("[Client] Padding file data and encrypting using AES CBC mode...")
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    # Trả về IV nối với ciphertext (để sử dụng cho giải mã)
    return iv + ciphertext

# --------- Thiết lập máy khách TCP ---------
HOST = '127.0.0.1'  # Thay đổi thành IP của server nếu chạy trên máy khác
PORT = 65432

# Đọc tệp cần chuyển (ở chế độ nhị phân)
input_filename = "file_to_send.txt"
print(f"=== Client: Reading file '{input_filename}' to send ===")
with open(input_filename, "rb") as f:
    file_data = f.read()
print(f"[Client] Read {len(file_data)} bytes from '{input_filename}'.")

print("\n=== Client: Step 1 - Connecting to Server ===")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print(f"[Client] Connected to server at {HOST}:{PORT}")

    # Bước 2: Nhận khóa công khai ECC từ server
    print("\n[Client] Step 2 - Receiving ECC public key from server...")
    ecc_pub = s.recv(4096).decode()
    print("[Client] Received ECC Public Key (hex):")
    print(ecc_pub)

    # Bước 3: Tạo khóa AES ngẫu nhiên (16 byte)
    print("\n[Client] Step 3 - Generating random AES key (16 bytes)...")
    aes_key = get_random_bytes(16)
    print("[Client] Generated AES Key (hex):", aes_key.hex())

    # Bước 4: Mã hóa khóa AES bằng cách sử dụng khóa công khai ECC của server (ECIES)
    print("\n[Client] Step 4 - Encrypting AES key using server's ECC public key...")
    encrypted_aes_key = ecc_encrypt(ecc_pub, aes_key)
    print("[Client] Encrypted AES Key (hex):", binascii.hexlify(encrypted_aes_key).decode())

    # Bước 5: Mã hóa dữ liệu tệp sử dụng AES ở chế độ CBC với khóa AES đã tạo
    print("\n[Client] Step 5 - Encrypting file data using AES CBC mode...")
    encrypted_file = aes_cbc_encrypt(file_data, aes_key)
    print("[Client] Encrypted File Data (IV + ciphertext, hex):", binascii.hexlify(encrypted_file).decode())

    # Bước 6: Đóng gói khóa AES đã mã hóa và dữ liệu tệp đã mã hóa thành JSON (đã mã hóa hex)
    print("\n[Client] Step 6 - Packaging encrypted data into JSON format...")
    data = {
        "encrypted_aes_key": binascii.hexlify(encrypted_aes_key).decode(),
        "encrypted_file": binascii.hexlify(encrypted_file).decode()
    }
    print("[Client] JSON Data to send:", data)

    # Bước 7: Gửi dữ liệu JSON đến server qua kết nối TCP
    print("[Client] Step 7 - Sending encrypted data to the server...")
    s.sendall(json.dumps(data).encode())
    print("[Client] Encrypted data sent successfully.")
