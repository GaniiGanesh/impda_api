from flask import Flask, request, jsonify, render_template, redirect, url_for
import json, os, requests, hashlib, base64
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# === Configuration ===
SECRET_SEED = "APIMPDS$9712Q"
IV_STR = "AP4123IMPDS@12768F"
API_URL = 'http://impds.nic.in/impdsmobileapi/api/getrationcard'
TOKEN = "91f01a0a96c526d28e4d0c1189e80459"
USER_AGENT = 'Dalvik/2.1.0 (Linux; U; Android 14; 22101320I Build/UKQ1.240624.001)'
ADMIN_PASSWORD = "ganesh@123"

app = Flask(__name__)

# === Utility Functions ===
def get_md5_hex(input_string: str) -> str:
    return hashlib.md5(input_string.encode('iso-8859-1')).hexdigest()

def generate_session_id() -> str:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return "28" + timestamp

def generate_key_material(session_id: str) -> str:
    inner_hash = get_md5_hex(SECRET_SEED)
    combined_string = inner_hash + session_id
    return get_md5_hex(combined_string)

def derive_aes_key(key_material: str) -> bytes:
    sha256 = hashlib.sha256(key_material.encode('utf-8')).digest()
    return sha256[:16]

def encrypt_payload(plaintext_id: str, session_id: str) -> str:
    key_material = generate_key_material(session_id)
    aes_key = derive_aes_key(key_material)
    iv = IV_STR.encode('utf-8')[:16]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext_id.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    b64_encoded = base64.b64encode(base64.b64encode(ciphertext)).decode('utf-8')
    return b64_encoded

# === API Key Handling ===
KEYS_FILE = "keys.json"

def load_keys():
    if not os.path.exists(KEYS_FILE):
        return {}
    with open(KEYS_FILE, 'r') as f:
        return json.load(f)

def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=4)

def is_key_valid(key):
    keys = load_keys()
    if key not in keys:
        return False, "Invalid API key"
    expiry = datetime.fromisoformat(keys[key]["expiry"])
    if datetime.now() > expiry:
        return False, "Key expired"
    return True, None

# === Routes ===
@app.route('/')
def home():
    return redirect('/admin')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            keys = load_keys()
            return render_template('admin.html', keys=keys)
        else:
            return "Invalid Password", 403
    return '''
    <form method="post">
        <h2>Admin Login</h2>
        <input type="password" name="password" placeholder="Enter password">
        <input type="submit" value="Login">
    </form>
    '''

@app.route('/create_key', methods=['POST'])
def create_key():
    name = request.form['name']
    hours = int(request.form['hours'])
    expiry = datetime.now() + timedelta(hours=hours)
    keys = load_keys()
    keys[name] = {"expiry": expiry.isoformat()}
    save_keys(keys)
    return redirect(url_for('admin', password=ADMIN_PASSWORD))

@app.route('/delete_key/<key>', methods=['POST'])
def delete_key(key):
    keys = load_keys()
    if key in keys:
        del keys[key]
        save_keys(keys)
    return redirect(url_for('admin', password=ADMIN_PASSWORD))

@app.route('/fetch', methods=['GET'])
def fetch():
    key = request.args.get('key', '').strip()
    aadhaar_input = request.args.get('aadhaar', '').strip()

    valid, msg = is_key_valid(key)
    if not valid:
        return jsonify({"error": msg}), 401

    if not aadhaar_input.isdigit() or len(aadhaar_input) != 12:
        return jsonify({"error": "Invalid Aadhaar number"}), 400

    try:
        session_id = generate_session_id()
        encrypted_id = encrypt_payload(aadhaar_input, session_id)

        headers = {'User-Agent': USER_AGENT, 'Content-Type': 'application/json; charset=utf-8'}
        payload = {"id": encrypted_id, "idType": "U", "userName": "IMPDS", "token": TOKEN, "sessionId": session_id}

        response = requests.post(API_URL, headers=headers, json=payload, timeout=15)
        data = response.json()
        data.pop("headers", None)
        data.pop("status_code", None)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === Run ===
if __name__ == '__main__':
    if not os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'w') as f:
            json.dump({}, f)
    app.run(host='0.0.0.0', port=5000, debug=True)
