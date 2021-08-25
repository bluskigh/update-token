import http.client
from json import loads, dumps
from os import environ
from base64 import b64decode

import rsa
from dotenv import load_dotenv
from jose import jwt

DOMAIN = CLIENT_ID = CLIENT_SECRET = AUDIENCE = GRANT_TYPE = None

def filter_jwks(jwks):
    return [key for key in jwks if 'kid' in key and key.get('use') == 'sig' and key.get('kty') == 'RSA']

def fetch_token():
    conn = http.client.HTTPSConnection(DOMAIN)
    payload = {'client_id': CLIENT_ID, 'client_secret': CLIENT_SECRET, 'audience': AUDIENCE, 'grant_type': GRANT_TYPE}
    headers = {'content-type': 'application/json'}
    conn.request('POST', '/oauth/token', dumps(payload), headers)
    res = conn.getresponse()
    data = res.read()
    # data is in byte 
    access_token = loads(data.decode()).get('access_token')
    return access_token


def verify_jwt(token):
    jwks = http.client.HTTPSConnection(DOMAIN)
    jwks.request('GET', '/.well-known/jwks.json')
    jwks = jwks.getresponse()
    jwks = loads(jwks.read().decode()).get('keys')
    jwks = filter_jwks(jwks)

    # decoding the header, converting to string by decoding, and loading using json
    header = loads(b64decode(token.split('.')[0]).decode())
    kid = header.get('kid')

    jwk = list(filter(lambda key: key.get('kid') == kid, jwks))

    if len(jwk) == 0:
        print('Could not find exact key')
        return None

    jwk = jwk[0] 
    try:
        jwt.decode(token=token, audience=AUDIENCE, key=jwk, algorithms=['RS256'], issuer=f'https://{DOMAIN}/')
        return True
    except jwt.ExpiredSignatureError as e:
        # fetch a new token from auth0 set as .env token value
        return False 


if __name__ == '__main__':
    # load .env key:value (s) to environment variables
    load_dotenv()
    # define values with relative env values
    DOMAIN = environ.get('DOMAIN')
    CLIENT_ID = environ.get('CLIENT_ID')
    CLIENT_SECRET = environ.get('CLIENT_SECRET')
    AUDIENCE = environ.get('AUDIENCE')
    GRANT_TYPE = environ.get('GRANT_TYPE')

    valid = None 

    with open('token.json', 'r') as f:
        try:
            token = loads(f.read()).get('token')
            # verify that the token is still useable
            if verify_jwt(token):
                valid = True
            else:
                valid = False
        except:
            # token has to exist, create it
            valid = False
    if not valid:
        # fetch new wtoken
        token = fetch_token()
        with open('token.json', 'w') as w:
            result = {'token': token}
            w.write(dumps(result))
            print('Successfully updated token, here it is\n')
            print(token)
