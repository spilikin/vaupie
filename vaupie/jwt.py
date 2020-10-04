from jose import jwt
import secrets
import logging
import time
import json
from uuid import uuid4

TOKEN_VALIDITY_PERIOD=60*60*24 # 24 Hours


def create_access_token(private_key_pem):
    claims = {
        'iss': "https://idp.example.de/",
        'aud': "https://prescriptionserver.telematik/",
        'sub': '1234567890',
        'iat': int(time.time()),
        'nbf': int(time.time()-1),
        'exp': int(time.time())+TOKEN_VALIDITY_PERIOD,
        'nonce': secrets.token_bytes(16).hex(),
        'acr': '1',
        'professionOID': '1.2.276.0.76.4.49',
        'given_name': 'Manfred',
        'family_name': 'Mustermann',
        'organizationName': "none",
        'idNummer': "0",
        'jti': str(uuid4())

    }
    logging.debug(f"Signing claims: {json.dumps(claims, indent=2)}")
    token = jwt.encode(claims, private_key_pem, algorithm='ES256')
    return token
