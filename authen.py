#! /bin/env python3
import db
import bcrypt
import requests
import re
import time
import secrets
import json

import jwt

import tornado.web


def hash_password(password: str):
    # Generate hash of password.
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

def verify_hash(password: str, hash: bytes):
    # Verify the password with the hash retrieved from table 'users'.
    return bcrypt.checkpw(password.encode('utf-8'), hash)

def get_jwt(url: str, id: int, password: str):
    # Construct a https request(protect id and password), and apply for a JWT token.
    # Should use by client.
    data = {
        'id' : str(id),
        'password' : str(password),
    }

    response = requests.post(url, data=data, verify=False)
    print(f'response: {response}')

    jwt_token = None
    if response.status_code == 200:
        try:
            response_json = response.json()
            jwt_token = response_json.get('jwt')
        except ValueError as e:
            print('Error: fail to get jwt_token')
            pass
    return jwt_token


def generate_jwt(user_id, secret:str , duration: int = 3600):
    # Generate JWT token according to user_id and secret. 
    # Should use by server.
    current_timestamp = int(time.time())
    payload = {
        "id": user_id,
        "iat": current_timestamp,
        "exp": current_timestamp + duration
    }
    token = jwt.encode(payload, secret, algorithm='HS256')
    return token


def verify_jwt(token: str, secret: str):
    # Verify whether a token is valid. You should retrieve the secret form table 'secrets'
    # before you call this method.
    ret = True
    try:
        decoded_payload = jwt.decode(token, secret, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        ret = False
    except jwt.InvalidTokenError:
        ret = False
    
    return ret


class Verifier(tornado.web.RequestHandler):
    authentication = db.DB('authen')
    pattern = r'^\d+$'
    regex_pattern = re.compile(pattern)

    def compute_etag(self):
        return None

    def post(self):
        id = self.get_argument('id')
        password = self.get_argument('password')
        print(f'id = {id}, password = {password}')

        if not Verifier.regex_pattern.match(str(id)):
            self.set_status(400)
            self.write('Bad Request: Invalid ID format')
            self.finish()
            return

        command = 'select hash from users where id = ?;'

        hash = Verifier.authentication.execute(command, (int(id),))

        print(f'hash is {hash}')
        print(f'type of hash {type(hash[0])}, type of password {type(password)}')

        if len(hash) != 1 or not verify_hash(password, hash[0][0]):
            self.set_status(400)
            self.write('Bad Request: Authentication failed')
            self.finish()
            return
        
        command2 = """
            INSERT INTO secrets (id, secret)
            VALUES (?, ?)
            ON CONFLICT(id) DO UPDATE SET
                secret = excluded.secret;
            """
        
        secret = secrets.token_urlsafe(32)
        try:
            Verifier.authentication.execute(command2, (id, secret))
            token = generate_jwt(id, secret)
        except Exception as e:
            self.set_status(500)
            self.write("Internal Server Error")
            self.finish()
            return

        self.set_status(200)
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"jwt": token}))
        self.finish()
        return


# for test
if __name__ == '__main__':
    import tornado.ioloop
    import tornado.httpserver
    import ssl

    app = tornado.web.Application([
        (r"/authen", Verifier),
    ])

    ssl_options = {
        "certfile": "server.crt",
        "keyfile": "server.key",
        "ca_certs": "server.crt",
    }

    http_server = tornado.httpserver.HTTPServer(app, ssl_options=ssl_options)

    http_server.listen(443)

    tornado.ioloop.IOLoop.current().start()






