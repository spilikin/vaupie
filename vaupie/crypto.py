from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# simple implementation of ECIES
# basen on example from https://bitbucket.org/andreas_hallof/vau-protokoll/src/master/erp/enc.py
def encrypt(bob_public_key: ec.EllipticCurvePublicKey, tag: bytearray, plaintext: bytearray):
    private_key = ec.generate_private_key(ec.BrainpoolP256R1())
    public_key = private_key.public_key()
    pn = public_key.public_numbers()

    shared_secret = private_key.exchange(ec.ECDH(), bob_public_key)

    hkdf = HKDF(algorithm=hashes.SHA256(), length=16,
            salt=None, info=tag
    )

    aes_key = hkdf.derive(shared_secret)
    aesgcm = AESGCM(aes_key)
    iv = secrets.token_bytes(12)

    ciphertext = aesgcm.encrypt(iv, plaintext, associated_data=None)
    
    x_str = format(pn.x, 'x').zfill(64)
    y_str = format(pn.y, 'x').zfill(64)

    return b'\1'+bytes.fromhex(x_str)+bytes.fromhex(y_str)+iv+ciphertext

def decrypt(response_key: bytes, ciphertext: bytes):
    aesgcm = AESGCM(response_key)
    iv = ciphertext[0:12]
    return aesgcm.decrypt(iv, ciphertext[12:], None)
