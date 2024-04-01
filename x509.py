# Copyright 2018 Simon Davy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# WARNING: the code in the gist generates self-signed certs, for the purposes of testing in development. 
# Do not use these certs in production, or You Will Have A Bad Time. 
#
# Caveat emptor
#

from datetime import datetime, timedelta
import ipaddress
import json
from jwcrypto import jwk, jwt
import base64


def generate_selfsigned_cert(hostname, key=None):
    """Generates self signed certificate for a hostname, and optional IP addresses."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    
    if not key:
        keys = json.load(open('keys.json')) 
        rsa_jwk = keys['RSA_key']
        rsa_key = jwk.JWK(**rsa_jwk)
        # export in PEM format
        pem_key = rsa_key.export_to_pem(private_key=True, password=None)
        # Load PEM key
        key = serialization.load_pem_private_key(pem_key, password=None)

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname)
    ])
 
    # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.    
    alt_names = [x509.DNSName(hostname)]
    
    san = x509.SubjectAlternativeName(alt_names)
    
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10*365))
        .add_extension(basic_contraints, False)
        .add_extension(san, False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(encoding=serialization.Encoding.DER)


def x5c_potential():
    hostname = "talao.co"
    a = generate_selfsigned_cert(hostname)
    return [base64.b64encode(a).decode()]

