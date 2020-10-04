import logging
import urllib
from .state import EndpointState
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def init_endpoint(endpoint: str, auth_token: str) -> EndpointState: 
    endpoint_state = EndpointState(base_url=endpoint, auth_token=auth_token)
    cert_url = urllib.parse.urljoin(endpoint, "VAUCertificate")

    logging.debug("Initialising the VAU Endpoint")
    logging.debug(f"Fetching VAU certificate from {cert_url}")

    r = requests.get(cert_url)
    if r.status_code != 200:
        exit(f"ERROR: Unable to fetch VAU Certificate, got response: {r.status_code}")
    
    vau_certificate = x509.load_der_x509_certificate(r.content)
    endpoint_state.x509 = vau_certificate.public_bytes(serialization.Encoding.DER).hex()

    return endpoint_state
