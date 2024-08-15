import json
import uuid
import logging
import sqlite3
import random 
import string
from jwcrypto import jwk
from oidc4vc_constante import client_data_pattern_oidc4vc

logging.basicConfig(level=logging.INFO)


def update_oidc4vc_verifier(client_id, data):
    return update(client_id, data, 'ebsi_verifier.db')
def read_oidc4vc_verifier(client_id):
    return read(client_id, 'ebsi_verifier.db')
def list_oidc4vc_verifier():
    return list('ebsi_verifier.db')
def delete_oidc4vc_verifier(client_id):
    return delete(client_id, 'ebsi_verifier.db')
def create_oidc4vc_verifier(mode, user=None):
    return create('ebsi_verifier.db', user, mode)

def update_oidc4vc_issuer(client_id, data):
    return update(client_id, data, 'ebsi_issuer.db')
def read_oidc4vc_issuer(client_id):
    return read(client_id, 'ebsi_issuer.db')
def list_oidc4vc_issuer():
    return list('ebsi_issuer.db')
def delete_oidc4vc_issuer(client_id):
    return delete(client_id, 'ebsi_issuer.db')
def create_oidc4vc_issuer(mode, user=None):
    return create('ebsi_issuer.db', user, mode)


def create(db, user, mode):
    letters = string.ascii_lowercase
    data = client_data_pattern_oidc4vc
    data['client_id'] = ''.join(random.choice(letters) for i in range(10))
    data['client_secret'] = str(uuid.uuid1())
    if db == 'verifier.db' and user != 'admin':
        data['standalone'] = 'on'
    if db in ['ebsi_issuer.db', 'ebsi_verifier.db']:
        key = jwk.JWK.generate(kty="EC", crv="P-256", alg="ES256")
    else: # db == 'issuer.db' 
        data['issuer_landing_page'] = mode.server + 'sandbox/op/issuer/' + data['client_id']
        # init with did:ethr
        key = jwk.JWK.generate(kty="EC", crv="secp256k1", alg="ES256K-R")
    data['jwk'] = key.export_private()
    if user:
        data['user'] = user
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = { "client_id": data['client_id'] ,"data":json.dumps(data)}
    try:
        c.execute("INSERT INTO client VALUES (:client_id,:data)", db_data)
    except Exception:
        logging.error('DB error')
        return None
    conn.commit()
    conn.close()
    return data['client_id']


def update(client_id, data, db):
    delete(client_id, db)
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = { "client_id": client_id,
            "data": data}
    try:
        c.execute("INSERT INTO client VALUES (:client_id,:data)", db_data)
    except Exception:
        return None
    conn.commit()
    conn.close()


def read(client_id, db):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = { 'client_id': client_id}
    c.execute('SELECT data FROM client WHERE client_id =:client_id ', db_data)
    client_data = c.fetchone()
    conn.close()
    return client_data[0] if client_data else None


def list(db):
    """ Return list of username """
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT client_id, data FROM client")
    db_select = c.fetchall()
    conn.close()
    return [item[1] for item in db_select]


def delete(client_id, db):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = {'client_id': client_id}
    try:
        c.execute("DELETE FROM client WHERE client_id =:client_id " , db_data)
    except Exception:
        return False
    conn.commit()
    conn.close()
    return True
