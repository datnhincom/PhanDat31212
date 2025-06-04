import socket
import threading
import getpass
from Crypto.Cipher import AES
import base64

# Hàm mã hóa tin nhắn
def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

# Hàm giải mã tin nhắn
def decrypt_message(encrypted_message, key):
    encrypted_data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Hàm gửi tin nhắn
def send_message(sock, key):
    while True:
        message = input("Nhập tin nhắn: ")
        encrypted_message = encrypt_message(message, key)
        sock.sendall(encrypted_message.encode('utf-8'))

# Hàm nhận tin nhắn
def receive_message(sock):
    while True:
        encrypted_message = sock.recv(1024).decode('utf-8')
        key = input("Nhập mã khóa để xem tin nhắn: ")
        try:
            decrypted_message = decrypt_message(encrypted_message, key)
            print(f"Tin nhắn: {decrypted_message}")
        except Exception:
            print("Mã khóa không đúng!")

# Thiết lập kết nối
def main():
    host = '172.16.0.132'  # Địa chỉ máy chủ
    port = 5000  # Cổng máy chủ

    # Tạo socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    key = getpass.getpass("Nhập mã khóa: ")

    # Tạo luồng cho việc gửi và nhận tin nhắn
    thread_send = threading.Thread(target=send_message, args=(sock, key))
    thread_receive = threading.Thread(target=receive_message, args=(sock,))

    thread_send.start()
    thread_receive.start()

if __name__ == "__main__":
    main()