from flask import Flask, request, jsonify, render_template
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os

app = Flask(__name__)

# Automatically use Render’s public URL if available, else localhost
RENDER_URL = os.getenv("RENDER_EXTERNAL_URL", "http://127.0.0.1:5000")

# Your secret key for AES encryption (should be 16, 24, or 32 bytes)
SECRET_KEY = b"thisisaverysecret"

# Dummy database of users and keys (can be replaced later)
api_keys = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin():
    return render_template('admin.html', keys=api_keys, base_url=RENDER_URL)

@app.route('/create_key', methods=['POST'])
def create_key():
    username = request.form.get('username')
    if not username:
        return jsonify({'error': 'Username required'}), 400
    if username in api_keys:
        return jsonify({'error': 'Key already exists'}), 400

    api_keys[username] = username
    return jsonify({'success': True, 'key': username})

@app.route('/fetch', methods=['GET'])
def fetch():
    aadhaar = request.args.get('aadhaar')
    key = request.args.get('key')

    if not aadhaar or not key:
        return jsonify({'error': 'Missing aadhaar or key'}), 400

    if key not in api_keys.values():
        return jsonify({'error': 'Invalid API key'}), 403

    # Dummy example response
    response = {
        'aadhaar': aadhaar,
        'status': 'Valid Aadhaar Found',
        'name': 'Ganesh Nayak',
        'state': 'Karnataka'
    }

    return jsonify(response)


if __name__ == '__main__':
    app.run(debug=True)
