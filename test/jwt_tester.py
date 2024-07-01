# 1) first create a virtual environment
#    python3 -m venv venv           # create virtual environment
#    source venv/bin/activate       # activate virtual environment
#    pip install flask PyJWT        # install necessary libraries
#
# 2) then to run
#    python3 ./jwt_tester.py
#
# 3) YARC is a good browser plugin to test with
#   https://chrome.google.com/webstore/detail/yet-another-rest-client/ehafadccdcdedbhcbddihehiodgcddpl/support
#
# 4) Get Token
#   GET http://127.0.0.1:5000
#   RESPONSE = {
#     "token": "eyJhbGciOiJIUzI1NiIs ... hB9yJCuM-2p0tlgsqeWsevbedGcs6jP6pSoSRCYjKcI"
#   }
#
# 5) Validate Token
#   POST http://127.0.0.1:5000/validate
#   payload = {
#     "token": "eyJhbGciOiJIUzI1NiIs ... hB9yJCuM-2p0tlgsqeWsevbedGcs6jP6pSoSRCYjKcI"
#   }
#   RESPONSE = {
#     "payload": {
#       "aud": "Secure PVAccess JWT Testing",
#       "exp": "Friday 17th May 2024 08:59:57",
#       "iat": "Friday 17th May 2024 08:29:57",
#       "iss": "http://127.0.0.1:5000/validate",
#       "kid": "2",
#       "nbf": "Friday 17th May 2024 08:29:57",
#       "sub": "user@epics.org"
#     },
#     "valid": true
#   }

import argparse
import datetime
import json
import random

import jwt
from flask import Flask, request, jsonify

# Parse command line arguments.
parser = argparse.ArgumentParser(description="JWT Tester")
parser.add_argument('--keys', help='JSON string to replace keys dictionary. Format: \'{"key":"value", ...}\'')

args = parser.parse_args()

# default set of keys (Random Passwords)
keys = {
    '1': 'EPICS Fail',
    '2': 'EPICS Never Fails',
    '3': 'Skepticism Rules',
    '4': 'Hope dies last',
    '5': 'BSOD',
}

# Update the keys dictionary if provided in command line arguments --keys
if args.keys:
    keys = json.loads(args.keys)

# run app
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


def generate_token():
    global allowed_token
    key_id, secret = random.choice(list(keys.items()))
    payload = {
        'iss': base_url + validate_route,
        'kid': key_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=token_duration_minutes),
        'iat': datetime.datetime.now(datetime.timezone.utc),
        'nbf': datetime.datetime.now(datetime.timezone.utc),  # Changed this line
        'sub': 'user@epics.org',
        'aud': aud
    }

    headers = {
        'kid': key_id,
    }

    allowed_token = jwt.encode(payload, secret, algorithm=encryption_algorithm, headers=headers)
    return allowed_token


@app.route(app_route)
def home():
    token = generate_token()
    return jsonify({json_token: token})


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
            date = datetime.datetime.fromtimestamp(payload[key])  # updated line
            payload[key] = date.strftime("%A %dth %B %Y %H:%M:%S")

        return jsonify({'valid': True, 'payload': payload})
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})


if __name__ == "__main__":
    app.run(port=port)
