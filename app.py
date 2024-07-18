from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
import base64
import os
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///crypto_webapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Define the database model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    encrypted_message = db.Column(db.String, nullable=False)
    key = db.Column(db.String, nullable=False)

    def __repr__(self):
        return f"<Message(id={self.id}, encrypted_message={self.encrypted_message}, key={self.key})>"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        message = request.json['message']
        key = os.urandom(16)
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
        encrypted_message = base64.b64encode(nonce + ciphertext).decode('utf-8')

        # Store encrypted message and key in the database
        new_message = Message(encrypted_message=encrypted_message, key=base64.b64encode(key).decode('utf-8'))
        db.session.add(new_message)
        db.session.commit()

        return jsonify({'encrypted_message': encrypted_message, 'key': base64.b64encode(key).decode('utf-8')})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        encrypted_message = request.json['encrypted_message']
        key = base64.b64decode(request.json['key'])
        encrypted_message_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
        nonce = encrypted_message_bytes[:16]
        ciphertext = encrypted_message_bytes[16:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted_message = cipher.decrypt(ciphertext).decode('utf-8')
        return jsonify({'decrypted_message': decrypted_message})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database tables created")
    app.run(debug=True)
