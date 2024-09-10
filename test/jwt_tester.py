import argparse
import base64
import datetime
import json
import random

import jwt
from flask import Flask, request, jsonify

# Parse command line arguments
parser = argparse.ArgumentParser(description="JWT Tester")
parser.add_argument('--keys', help='JSON string to replace keys dictionary. Format: \'{"key":"value", ...}\'')

args = parser.parse_args()

# Default set of keys (Random Passwords)
keys = {
    '1': 'EPICS Fail',
    '2': 'EPICS Never Fails',
    '3': 'Skepticism Rules',
    '4': 'Hope dies last',
    '5': 'BSOD',
}

# Predefined list of usernames and passwords
user_credentials = {
    'george': 'password123',
    'michael': 'securepass',
    'anna': 'mypassword',
}

# Update the keys dictionary if provided in command line arguments --keys
if args.keys:
    keys = json.loads(args.keys)

# Run app
app = Flask(__name__)

# Configuration
port = 5000
base_url = 'http://127.0.0.1:' + str(port)
app_route = '/'
validate_route = '/validate'
encryption_algorithm = 'HS256'
aud = 'Secure PVAccess JWT Testing'
json_token = 'token'
token_duration_minutes = 30

allowed_token = None


def generate_token(username):
    global allowed_token
    key_id, secret = random.choice(list(keys.items()))
    payload = {
        'iss': base_url + validate_route,
        'kid': key_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=token_duration_minutes),
        'iat': datetime.datetime.now(datetime.timezone.utc),
        'nbf': datetime.datetime.now(datetime.timezone.utc),
        'sub': f'{username}@epics.org',
        'aud': aud
    }

    headers = {
        'kid': key_id,
    }

    allowed_token = jwt.encode(payload, secret, algorithm=encryption_algorithm, headers=headers)
    return allowed_token


@app.route(app_route)
def home():
    user = request.args.get('user')
    password_base64 = request.args.get('pass')

    if not user or not password_base64:
        return jsonify({'error': 'Missing user or pass parameter'}), 400

    try:
        password = base64.b64decode(password_base64).decode('utf-8')
    except Exception as e:
        return jsonify({'error': 'Invalid base64 encoding'}), 400

    if user in user_credentials and user_credentials[user] == password:
        token = generate_token(user)
        return jsonify({json_token: token})
    else:
        return jsonify({'error': 'Invalid username or password'}), 401


@app.route(validate_route, methods=['POST'])
def validate():
    token = request.json[json_token]

    # Decode the token without verifying to get the header fields
    unverified_header = jwt.get_unverified_header(token)

    # Get the Key ID (kid) from the header
    key_id_from_token = unverified_header['kid']

    # Use the Key ID to fetch the corresponding secret from the keys dictionary
    secret_from_dictionary = keys[key_id_from_token]

    try:
        # Then, decode the token again, this time verifying the signature
        payload = jwt.decode(token, secret_from_dictionary, algorithms=[encryption_algorithm], audience=aud)

        # Format times
        for key in ['exp', 'iat', 'nbf']:
            date = datetime.datetime.fromtimestamp(payload[key])
            payload[key] = date.strftime("%A %dth %B %Y %H:%M:%S")

        return jsonify({'valid': True, 'payload': payload})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})


if __name__ == "__main__":
    app.run(port=port)
