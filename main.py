import uuid
import hashlib
import requests

hasher = hashlib.sha256()


def generate_code_verifier():
    return str(uuid.uuid4().hex)


def generate_code_challenge(code_verifier):
    hasher = hashlib.sha256()
    hasher.update(code_verifier.encode('utf-8'))
    return hasher.hexdigest()


def get_auth_code(username, code_challenge):
    url = 'http://localhost:5000/authorize'
    headers = {'Content-Type': 'application/json'}
    payload = {'username': username, 'code_challenge': code_challenge}
    response = requests.post(url, json=payload, headers=headers)

    if response.status_code != 200:
        print('Failed to get auth code:', response.json()['error'])
        return None
    auth_code = response.json()["auth_code"]
    print('Success. Auth code:', auth_code)
    return auth_code

def get_jwt_token(username,code_verifier, auth_code):
    url = 'http://localhost:5000/oauth/token'
    headers = {'Content-Type': 'application/json'}
    payload = {'username': username, 'code_verifier': code_verifier, 'auth_code': auth_code}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        print('Failed to get token:', response.json()['error'])
        return None
    token =  response.json()["token"]
    print('Success. Token:', token)
    return token

def get_protected_source(jwt_token):
    url = 'http://localhost:5000/protected'
    headers = {'Content-Type': 'application/json'}
    payload = {'token': jwt_token}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code != 200:
        print('Failed to get protected source:', response.json()['error'])
        return None
    print(response.json()['msg'])

def start(username):
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    auth_code = get_auth_code(username, code_challenge)
    jwt_token = get_jwt_token(username,code_verifier,auth_code)
    get_protected_source(jwt_token)
    return


start('Pelmen964')
