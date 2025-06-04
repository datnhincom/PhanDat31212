from flask import Flask, render_template
from flask_socketio import SocketIO
import base64
from Crypto.Cipher import AES

app = Flask(__name__)
socketio = SocketIO(app)

def encrypt_message(message, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_message(encrypted_message, key):
    encrypted_data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('send_message')
def handle_send_message(data):
    encrypted_message = encrypt_message(data['message'], data['key'])
    socketio.emit('receive_message', {'encrypted_message': encrypted_message}, broadcast=True)

@socketio.on('decrypt_message')
def handle_decrypt_message(data):
    try:
        decrypted_message = decrypt_message(data['encrypted_message'], data['key'])
        socketio.emit('decrypted_message', {'decrypted_message': decrypted_message}, to=data['sid'])
    except Exception:
        socketio.emit('decrypted_message', {'decrypted_message': 'Mã khóa không đúng!'}, to=data['sid'])

if __name__ == '__main__':
    socketio.run(app, debug=True)