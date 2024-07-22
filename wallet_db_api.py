import json
import uuid
import logging
import sqlite3
import random 
import string

logging.basicConfig(level=logging.INFO)


def update_wallet_verifier(id, data):
    return update(id, data, 'wallet_verifier.db')
def read_wallet_verifier(id):
    return read(id, 'wallet_verifier.db')
def list_wallet_verifier():
    return list('wallet_verifier.db')
def delete_wallet_verifier(id):
    return delete(id, 'wallet_verifier.db')
def create_wallet_verifier(data):
    return create(data, 'wallet_verifier.db')


def update_wallet_credential(id, data):
    return update(id, data, 'wallet_credential.db')
def read_wallet_credential(id):
    return read(id, 'wallet_credential.db')
def list_wallet_credential():
    return list('wallet_credential.db')
def delete_wallet_credential(id):
    return delete(id, 'wallet_credential.db')
def create_wallet_credential(data):
    return create(data, 'wallet_credential.db')


def update_wallet_issuer(id, data):
    return update(id, data, 'wallet_issuer.db')
def read_wallet_issuer(id):
    return read(id, 'wallet_issuer.db')
def list_wallet_issuer():
    return list('wallet_issuer.db')
def delete_wallet_issuer(id):
    return delete(id, 'wallet_issuer.db')
def create_wallet_issuer(data):
    return create(data, 'wallet_issuer.db')


def create(data: any, db: str):
    if not isinstance(data, str):
        data = json.dumps(data)
    letters = string.ascii_lowercase
    id = ''.join(random.choice(letters) for i in range(10))
    data['id'] = id
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = {
        "id": id,
        "data": data
    }
    try:
        c.execute("INSERT INTO client VALUES (:id,:data)", db_data)
    except Exception:
        logging.error('DB error')
        return None
    conn.commit()
    conn.close()
    return id


def update(id, data, db):
    delete(id, db)
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = {
        "id": id,
        "data": data
    }
    try:
        c.execute("INSERT INTO client VALUES (:id,:data)", db_data)
    except Exception:
        return None
    conn.commit()
    conn.close()


def read(id, db):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = {
        'id': id
    }
    c.execute('SELECT data FROM client WHERE id =:id ', db_data)
    client_data = c.fetchone()
    conn.close()
    return client_data[0] if client_data else None


def list(db):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    c.execute("SELECT id, data FROM client")
    db_select = c.fetchall()
    conn.close()
    return [item[1] for item in db_select]


def delete(id, db):
    conn = sqlite3.connect(db)
    c = conn.cursor()
    db_data = {
        'id': id
    }
    try:
        c.execute("DELETE FROM client WHERE id =:id " , db_data)
    except Exception:
        return False
    conn.commit()
    conn.close()
    return True
