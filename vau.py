#!/usr/bin/env python3
import secrets
import sys
import urllib
import requests
import argparse
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from vaupy.state import State, EndpointState, RequestState, StateVersionError
import vaupy.ecies as ecies
import io
import re


STATE_FILENAME = f"{Path.home()}/.vaupy.json"

try:
    state = State.load(STATE_FILENAME)
except IOError:
    state = State()
    state.save(STATE_FILENAME)
except StateVersionError:
    state = State()
    state.save(STATE_FILENAME)

def init(endpoint: str, auth_token: str, verbose: bool): 
    endpoint_state = EndpointState(base_url=endpoint, auth_token=auth_token)
    cert_url = urllib.parse.urljoin(endpoint, "VAUCertificate")
    if verbose:
        print("Initialising the VAU Endpoint")
        print(f"  - Fetching VAU certificate from {cert_url}")

    r = requests.get(cert_url)
    if r.status_code != 200:
        exit(f"ERROR: Unable to fetch VAU Certificate, got response: {r.status_code}")
    
    vau_certificate = x509.load_der_x509_certificate(r.content)
    endpoint_state.x509 = vau_certificate.public_bytes(serialization.Encoding.DER).hex()

    if verbose:
        print(f"  - Configuting '{endpoint}' as default in config file {config_filename}")

    state.endpoint = endpoint_state
    state.save(STATE_FILENAME)

    if verbose:
        print(f"Done")

def request(state: State): 
    request_id = secrets.token_bytes(16).hex()
    response_key = secrets.token_bytes(16).hex()

    plaintext = b'1 '+state.endpoint.auth_token.encode()+b' '+request_id.encode()+b' '+response_key.encode()+b' '

    request_bytes = sys.stdin.buffer.read()
    plaintext += request_bytes

    cert = x509.load_der_x509_certificate(bytes.fromhex(state.endpoint.x509))
    vau_public_key = cert.public_key()
    ecies_message = ecies.encrypt(vau_public_key, b'ecies-vau-transport', plaintext)

    vau_url = urllib.parse.urljoin(state.endpoint.base_url, f"VAU/{state.endpoint.userpseudonym}")
    response = requests.post(vau_url, data=ecies_message, headers={'Content-type': 'application/octet-stream'}, stream=True)

    ciphertext = response.raw.read()

    state.endpoint.userpseudonym = response.headers['userpseudonym']
    state.save(STATE_FILENAME)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aesgcm = AESGCM(bytes.fromhex(response_key))
    iv = ciphertext[0:12]
    plaintext = aesgcm.decrypt(ciphertext[0:12], ciphertext[12:], None)

    firstline = io.BytesIO(plaintext).readline()
    plaintext = plaintext[len(firstline):]

    matches = re.search("([^\s]*) ([^\s]*) (.*)", firstline.decode('utf-8').rstrip('\n').rstrip('\r'))
    print (matches[3])
    print (plaintext.decode('utf-8'))

# Prints the Authorization HTTP Header to stdout
def authorization(state: State):
    print (f"Authorization:Bearer {state.endpoint.auth_token}")


parser = argparse.ArgumentParser(prog='vaupie', description='Perform VAU-Client commands')
parser.add_argument('action', choices=['init', 'req', 'auth'], help='action to execute')
parser.add_argument('endpoint', nargs="?", type=str, help='VAU Endpoint, e.g. http://localhost:3000/')
parser.add_argument('token', nargs="?", type=str, help='JWT Auth Token')
parser.add_argument("--verbose", "-v", help="increase output verbosity", action="store_true")

args = parser.parse_args()

if args.action == "init" and args.endpoint == None:
    parser.error("Endpoint URL reqired")

if args.action == "init" and args.token == None:
    parser.error("JWT Auth token reqired")

if args.action == "init":
    init(args.endpoint, args.token, verbose=args.verbose)
else:
    if state.endpoint == None:
        exit("error: endpoint is not configured. Issue 'vau.py init' command first.")

    if args.action == "req":
        request(state=state)
    elif args.action == "auth":
        authorization(state=state)
    else:
        parser.error(f"invalid action: {args.action}")        
    

