import hashlib
import hmac
import time
import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

API_KEY = str(os.getenv("API_KEY"))

def check_auth(data):
    check_hash = data.pop('hash', None)
    data_check_string = '\n'.join([f'{k}={v}' for k, v in sorted(data.items())])
    secret_key = hashlib.sha256(API_KEY.encode()).digest()
    h = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    return h == check_hash and time.time() - int(data['auth_date']) < 86400  # valid for 1 day


@app.route('/auth/telegram', methods=['GET'])
def telegram_auth():
    data = request.args.to_dict()

    if check_auth(data):
        # Authentication successful
        user_full_name = data['first_name'] + ' ' + data.get('last_name', '')
        return jsonify({'status': 'ok', 'name': user_full_name})
    else:
        # Authentication failed
        return jsonify({'status': 'error', 'message': 'Invalid authentication'}), 403

if __name__ == '__main__':
    app.run(debug=True)