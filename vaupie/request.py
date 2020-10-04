import logging
import requests
import sys
import requests
import secrets
import urllib
import io
import re
from cryptography import x509
import vaupie.crypto as crypto

def post_request(userpseudonym:str, base_url: str, cert: str, auth_token: str, file) -> bytes: 
    request_id = secrets.token_bytes(16).hex()
    response_key = secrets.token_bytes(16).hex()

    plaintext = b'1 '+auth_token.encode()+b' '+request_id.encode()+b' '+response_key.encode()+b' '

    request_bytes = file.read()

    plaintext += request_bytes

    logging.debug("Plaintext VAU request:")
    logging.debug(plaintext.decode('utf-8'))

    cert = x509.load_der_x509_certificate(bytes.fromhex(cert))
    vau_public_key = cert.public_key()
    ecies_message = crypto.encrypt(vau_public_key, b'ecies-vau-transport', plaintext)

    logging.debug(f"Ciphertext: {ecies_message.hex()}")

    vau_url = urllib.parse.urljoin(base_url, f"VAU/{userpseudonym}")
    response = requests.post(vau_url, data=ecies_message, headers={'Content-type': 'application/octet-stream'}, stream=True)

    if not response.ok:
        exit(f"{response.status_code} {response.text}")

    ciphertext = response.raw.read()

    userpseudonym = response.headers['userpseudonym']
    logging.debug(f"User pseudonym: {userpseudonym}")

    plaintext = crypto.decrypt(bytes.fromhex(response_key), ciphertext)

    firstline = io.BytesIO(plaintext).readline()
    plaintext = plaintext[len(firstline):]

    matches = re.search("([^\s]*) ([^\s]*) (.*)", firstline.decode('utf-8').rstrip('\n').rstrip('\r'))
    response = matches[3].encode() + b'\r\n' + plaintext

    logging.debug(response)

    return (userpseudonym, matches[1], matches[2], response)

