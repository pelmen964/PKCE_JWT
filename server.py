import hashlib
import jwt
import time
from flask import Flask, request, jsonify
import logging
import uuid
app = Flask(__name__)
app.logger.setLevel(logging.INFO)


# Секретный ключ для подписи токенов
SECRET_KEY = 'supersecret_server_key'

# Список пользователей и их токенов
users_to_auth = {}
# authed_users = {}

def generate_auth_code():
    return str(uuid.uuid4().hex)

def generate_code_challenge(code_verifier):
    hasher = hashlib.sha256()
    hasher.update(code_verifier.encode('utf-8'))
    return hasher.hexdigest()

def generate_token(payload, expires_in=96400):
    iat = int(time.time())
    exp = iat + expires_in
    payload.update({'iat': iat, 'exp': exp})
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256') # HMAC(Механизм проверки целостности информации) с SHA256
    return token

def verify_token(token):
    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded_token
    except jwt.ExpiredSignatureError:
        return 'Токен истек'
    except jwt.InvalidTokenError:
        return 'Неверный токен'

@app.route('/authorize', methods=['POST'])
def send_auth_code():
    username = request.json.get('username')
    code_challenge = request.json.get('code_challenge')

    if code_challenge in users_to_auth:
        return jsonify({'error': 'Пользователь уже существует'}), 401

    auth_code = generate_auth_code()
    # users[code_challenge] = [auth_code,""]
    users_to_auth[username] = [code_challenge, auth_code]

    print("Usename: ", username, "auth_code: ", auth_code)

    return jsonify({'auth_code': auth_code}),200

@app.route('/oauth/token', methods=['POST'])
def send_token_user():

    print(request.json)

    username = request.json.get('username')
    auth_code = request.json.get('auth_code')
    code_verifier = request.json.get('code_verifier')

    new_code_challenger = generate_code_challenge(code_verifier)
    if username not in users_to_auth:
        return jsonify({'error': 'Сначала пройдите антефикацию'}), 401
    if new_code_challenger != users_to_auth[username][0]:
        return jsonify({'error': 'Не валидный код верефицирования'}), 401
    if auth_code != users_to_auth[username][1]:
        return jsonify({'error': 'Не валидный код аунтефикации'}), 401

    jwt_token = generate_token({'username':username})
    users_to_auth[username] = ["Valid", "Valid"]
    # authed_users[username] = jwt_token

    return jsonify({'token': jwt_token}),200

@app.route('/protected', methods=['POST'])
def protected_source():

    token = request.json.get('token')
    decoded_token = verify_token(token)
    if type(decoded_token) is str:
        return jsonify({'error': decoded_token}),401

    return jsonify({'msg': "Доступ разрешён"}),200

app.run()