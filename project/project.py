import uuid
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import base64

#Class KeyStore manages RSA key pairs.
class KeyStore:
    def __init__(self):
        self.keys = []

    #Function generates an RSA key pair with a specified expiration timestamp
    def generate_key(self, expires_in_seconds):
        private_key = rsa.generate_private_key( #creates private key using RSA key generation
            public_exponent = 65537,
            key_size = 2048,
            backend = default_backend()
        )
        private_pem = private_key.private_bytes( 
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ).decode('utf-8')

        public_key = private_key.public_key()

        kid = str(uuid.uuid4())
        expiry = datetime.now() + timedelta(seconds = expires_in_seconds) #creates an expiry timestamp
        key_entry = {
            'kid': kid,
            'private_key_pem': private_pem,
            'public_key': public_key,
            'expiry': expiry
        }
        self.keys.append(key_entry)
        return key_entry
    
    #Function gets all the keys that have not been expired.
    def get_valid_keys(self):
        now = datetime.now()
        keyList = []
        for key in self.keys:
            if key['expiry'] > now:
                keyList.append(key)

        return keyList

    #Function gets all the keys that have been expired.
    def get_expired_keys(self):
        now = datetime.now()
        keyList = []
        for key in self.keys:
            if key['expiry'] <= now:
                keyList.append(key)

        return keyList

    #Function gets the signing key, which can be expired or valid. 
    def get_signing_key(self, expired = False):
        if expired:
            expired_keys = self.get_expired_keys()
            if not expired_keys:
                return self.generate_key(expires_in_seconds = -3600)
            return expired_keys[0]
        else:
            valid_keys = self.get_valid_keys()
            if not valid_keys:
                return self.generate_key(expires_in_seconds = 3600)
            return valid_keys[0]

#Function converts the RSA public key into JWK format.
def jwk_from_public_key(public_key, kid):
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder = 'big')
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder = 'big')

    n_b64 = base64.urlsafe_b64encode(n_bytes).decode('utf-8').rstrip('=')
    e_b64 = base64.urlsafe_b64encode(e_bytes).decode('utf-8').rstrip('=')

    return {
        'kty': 'RSA',
        'kid': kid,
        'use': 'sig',
        'n': n_b64,
        'e': e_b64,
    }

#app is used to do different coding depending on the route
app = Flask(__name__)
app.keystore = KeyStore()


@app.route('/.well-known/jwks.json', methods = ['GET'])
#For public keys, JWKS enpoint is used.
def jwks():
    valid_keys = app.keystore.get_valid_keys()
    
    jwks_list = []
    for key in valid_keys:
        jwks_list.append(jwk_from_public_key(key['public_key'], key['kid']))

    return jsonify({'keys': jwks_list})


@app.route('/auth', methods = ['POST'])
#auth endpoint is used to issue JWTS, which are either expired or not expired.
def auth():
    expired = 'expired' in request.args
    if not expired:
        key_entry = app.keystore.get_signing_key(expired = expired)
        headers = {
            'kid': key_entry['kid'],
            'alg': 'RS256'
        }
        payload = {
            'sub': 'fake_user',
            'iat': int(datetime.now().timestamp()),
            'exp': int(key_entry['expiry'].timestamp())
        }
        token = jwt.encode(
            payload,
            key_entry['private_key_pem'],
            algorithm = 'RS256',
            headers = headers
        )
        return jsonify({'token': token})
    else:
        yesterday = datetime.now() - timedelta(days = 1)
        key_entry = app.keystore.get_signing_key(expired = expired)
        headers = {
            'kid': key_entry['kid'],
            'alg': 'RS256'
        }
        payload = {
            'sub': 'fake_user',
            'iat': int(datetime.now().timestamp()),
            'exp': int(yesterday.timestamp())
        }
        token = jwt.encode(
            payload,
            key_entry['private_key_pem'],
            algorithm = 'RS256',
            headers = headers
        )
        return jsonify({'token': token})

#Serves HTTP on port 8080
if __name__ == '__main__':
    app.run(port = 8080)