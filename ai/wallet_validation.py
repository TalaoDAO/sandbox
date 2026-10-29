"""Deterministic wallet diagnostics. No LLM, registry publication or notifications."""
import base64
import hashlib
import io
import fcntl
import logging
import ipaddress
import json
import re
import socket
import time
import unicodedata
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse, urljoin

import cbor2
import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from jwcrypto import jwk, jws

MAX_INPUT_BYTES = 1024 * 1024
HASHES = {'sha-256': 'sha256', 'sha-384': 'sha384', 'sha-512': 'sha512'}
ALGORITHMS = ['ES256', 'ES384', 'ES512', 'EdDSA', 'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']

class InputError(ValueError):
    """Malformed user input (HTTP 400)."""

class FetchError(ValueError):
    """Remote diagnostic resource could not be retrieved (HTTP 502)."""

def decode_b64(value, urlsafe=False):
    if not isinstance(value, str) or not value or len(value) > MAX_INPUT_BYTES * 2:
        raise InputError('Missing or oversized base64 input')
    try:
        pattern = r'[A-Za-z0-9_-]+={0,2}' if urlsafe else r'[A-Za-z0-9+/]+={0,2}'
        if not re.fullmatch(pattern, value):
            raise ValueError('invalid alphabet')
        return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_' if urlsafe else None, validate=True)
    except Exception as exc:
        raise InputError('Invalid base64 encoding') from exc

def decode_wallet_input(value):
    try:
        result = decode_b64(value, urlsafe=isinstance(value, str) and ('-' in value or '_' in value)).decode('utf-8').strip()
    except UnicodeDecodeError as exc:
        raise InputError('Input is not UTF-8') from exc
    if not result or len(result.encode()) > MAX_INPUT_BYTES:
        raise InputError('Empty or oversized input')
    return result


def decode_wallet_vc_input(value):
    """Accept base64(UTF-8 credential) and a directly base64-encoded mdoc CBOR.

    A wallet may send the OIDC4VCI mdoc credential itself, whereas text formats
    and some wallet versions use a second base64 envelope around that string.
    Only a recognized CBOR document can bypass the UTF-8 text envelope.
    """
    try:
        text = decode_wallet_input(value)
    except InputError as text_error:
        try:
            if detect_format(value) == 'mdoc':
                return value
        except InputError:
            pass
        raise text_error
    if text.startswith('{'):
        data = json_object(text)
        if isinstance(data.get('issuerSigned'), str):
            # AltMe sends jsonEncode(CredentialModel.data): its signed mdoc is
            # nested in issuerSigned alongside display-only claims. Analyze the
            # actual CBOR, never the copied credentialSubject display values.
            signed = cbor_document(data['issuerSigned'])
            if 'issuerAuth' not in signed or 'nameSpaces' not in signed:
                raise InputError('Wallet issuerSigned must contain an IssuerSigned mdoc')
            document = {'issuerSigned': signed}
            if 'docType' in data:
                if not isinstance(data['docType'], str) or not data['docType']:
                    raise InputError('Wallet mdoc docType must be a nonempty string')
                document['docType'] = data['docType']
            return base64.urlsafe_b64encode(cbor2.dumps(document)).decode('ascii')
    return text


def encode_wallet_report(report):
    """ASCII-compatible Markdown for wallets decoding base64 bytes as Latin-1.

    ASCII has the same representation in UTF-8 and Latin-1. Typographic symbols
    become explicit text and accents are transliterated. Remaining non-ASCII
    characters use explicit Unicode escapes; no HTML entity support is required.
    """
    replacements = {'\u2014': '-', '\u2013': '-', '\u2011': '-', '\u2010': '-',
                    '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
                    '\u00a0': ' ', '\u202f': ' ', '\u2026': '...', '\u00a7\u00a7': 'sections ',
                    '\u00a7': 'section ', '\u2192': '->', '\u2190': '<-', '\u2264': '<=',
                    '\u2265': '>=', '\u2260': '!=', '\u2713': 'PASS', '\u2714': 'PASS',
                    '\u2717': 'FAIL', '\u2718': 'FAIL', '\u26a0': 'WARNING', '\ufe0f': '',
                    '\u0153': 'oe', '\u0152': 'OE', '\u00e6': 'ae', '\u00c6': 'AE',
                    '\u00df': 'ss', '\u00f8': 'o', '\u00d8': 'O', '\u0142': 'l', '\u0141': 'L'}
    for before, after in replacements.items():
        report = report.replace(before, after)
    report = ''.join(c for c in unicodedata.normalize('NFKD', report) if not unicodedata.combining(c))
    return base64.b64encode(report.encode('ascii', errors='backslashreplace')).decode('ascii')

def json_object(raw):
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise InputError(f'Duplicate JSON key: {key}')
            obj[key] = value
        return obj
    try:
        obj = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, TypeError) as exc:
        raise InputError('Invalid JSON object') from exc
    if not isinstance(obj, dict):
        raise InputError('Expected a JSON object')
    return obj

def decode_jwt(token):
    if not isinstance(token, str) or len(token) > MAX_INPUT_BYTES:
        raise InputError('Invalid JWT')
    parts = token.split('.')
    if len(parts) != 3 or not all(re.fullmatch(r'[A-Za-z0-9_-]+', p) for p in parts):
        raise InputError('Expected a compact signed JWT')
    return json_object(decode_b64(parts[0], True)), json_object(decode_b64(parts[1], True))

def compact_jwt(value):
    try:
        decode_jwt(value)
        return True
    except InputError:
        return False

def cbor_document(value):
    raw = decode_b64(value, urlsafe=('-' in value or '_' in value))
    try:
        stream = io.BytesIO(raw)
        try:
            decoder = cbor2.CBORDecoder(stream, read_size=1)
        except TypeError:
            # cbor2 5.6.x has no read_size argument and does not buffer ahead.
            decoder = cbor2.CBORDecoder(stream)
        obj = decoder.decode()
        if stream.read(1) or not isinstance(obj, dict):
            raise ValueError('trailing bytes or invalid root')
        return obj
    except Exception as exc:
        raise InputError('Invalid mdoc CBOR') from exc

def detect_format(value):
    if not isinstance(value, str) or not value.strip():
        raise InputError('Empty credential')
    value = value.strip()
    if value.startswith(('{', '[')):
        obj = json_object(value)
        if '@context' in obj and 'type' in obj:
            return 'jsonld'
        raise InputError('JSON-LD requires @context and type')
    if '~' in value:
        decode_jwt(value.split('~')[0])
        return 'sd-jwt'
    if compact_jwt(value):
        header, _ = decode_jwt(value)
        return 'sd-jwt' if header.get('typ') in ('dc+sd-jwt', 'vc+sd-jwt') else 'jwt'
    obj = cbor_document(value)
    if ('issuerAuth' in obj and 'nameSpaces' in obj) or 'issuerSigned' in obj or 'documents' in obj:
        return 'mdoc'
    raise InputError('Unknown credential format')

def version(value):
    value = str(value or '1.0').strip().lower()
    if value in ('1.0', 'final', '1_0'):
        return '1.0'
    if value not in {str(n) for n in range(11, 19)}:
        raise InputError('Unsupported OIDC4VCI version')
    return value

def https_identifier(value):
    if not isinstance(value, str):
        raise InputError('Missing HTTPS identifier')
    p = urlparse(value)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.query or p.fragment:
        raise InputError('Identifier must be HTTPS without credentials, query or fragment')
    return value

def well_known(identifier, name, final=True):
    https_identifier(identifier)
    p = urlparse(identifier)
    if final:
        return f'{p.scheme}://{p.netloc}/.well-known/{name}{p.path}'
    return identifier.rstrip('/') + '/.well-known/' + name

def public_url(url):
    p = urlparse(url)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.fragment:
        raise InputError('Remote URLs must use HTTPS without credentials or fragments')
    try:
        addresses = socket.getaddrinfo(p.hostname, p.port or 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise FetchError('Remote host cannot be resolved') from exc
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise InputError('Private or non-public network URLs are prohibited')

def fetch(url, accept='application/json'):
    """Bounded requests; explicitly check every redirect target."""
    try:
        for _ in range(4):
            public_url(url)
            with requests.get(url, headers={'Accept': accept}, timeout=(4, 10), stream=True, allow_redirects=False) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get('Location')
                    if not location:
                        raise FetchError('Redirect without Location')
                    url = urljoin(url, location)
                    continue
                if response.status_code != 200:
                    raise FetchError(f'Remote HTTP {response.status_code}')
                chunks, size = [], 0
                for chunk in response.iter_content(65536):
                    size += len(chunk)
                    if size > MAX_INPUT_BYTES:
                        raise FetchError('Remote response exceeds size limit')
                    chunks.append(chunk)
                return b''.join(chunks), response.headers.get('Content-Type', '').split(';')[0].strip().lower()
        raise FetchError('Too many redirects')
    except requests.RequestException as exc:
        raise FetchError('Remote resource unavailable') from exc

def fetch_json(url):
    raw, content_type = fetch(url)
    if content_type != 'application/json' and not content_type.endswith('+json'):
        raise FetchError('Expected JSON Content-Type')
    try:
        return json_object(raw)
    except InputError as exc:
        raise FetchError('Remote resource is not a JSON object') from exc

def issuer_data(qrcode, draft):
    draft = version(draft)
    params = parse_qs(urlparse(qrcode).query, keep_blank_values=True)
    names = [n for n in ('credential_offer', 'credential_offer_uri') if n in params]
    if len(names) != 1 or len(params[names[0]]) != 1 or not params[names[0]][0]:
        raise InputError('Provide exactly one credential_offer or credential_offer_uri')
    offer = fetch_json(params[names[0]][0]) if names[0].endswith('_uri') else json_object(params[names[0]][0])
    issuer = https_identifier(offer.get('credential_issuer'))
    ids = offer.get('credential_configuration_ids')
    comments = []
    if draft == '1.0' or int(draft) >= 13:
        if not isinstance(ids, list) or not ids or any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids):
            raise InputError('credential_configuration_ids must contain unique, nonempty strings')
    modern = draft == '1.0' or int(draft) >= 16
    raw, ct = fetch(well_known(issuer, 'openid-credential-issuer', modern), 'application/json')
    if ct == 'application/jwt':
        header, metadata = decode_jwt(raw.decode())
        if header.get('x5c'):
            comments.extend(certificate_checks(header['x5c']))
            try:
                cert=x509.load_der_x509_certificate(decode_b64(header['x5c'][0]))
                verifier=jws.JWS(); verifier.allowed_algs=ALGORITHMS
                verifier.deserialize(raw.decode()); verifier.verify(jwk.JWK.from_pyca(cert.public_key()))
                comments.append('PASS: signed metadata JWS verified against supplied leaf certificate.')
            except Exception:
                comments.append('ERROR: signed metadata JWS signature could not be verified.')
        # Diagnostics may inspect untrusted metadata but never claim a trusted signature.
        comments.append('NOT_VERIFIED: signed issuer metadata: signer trust and signature are not established; metadata is diagnostic input only.')
        if header.get('typ') != 'openidvci-issuer-metadata+jwt' or metadata.get('sub') != issuer or not isinstance(metadata.get('iat'), int) or isinstance(metadata.get('iat'), bool):
            comments.append('ERROR: invalid signed issuer metadata typ/sub/iat.')
        if header.get('alg') not in ALGORITHMS:
            comments.append('ERROR: forbidden or unsupported metadata signing algorithm.')
        if 'exp' in metadata and (not isinstance(metadata['exp'], (int,float)) or metadata['exp'] <= time.time()):
            comments.append('ERROR: expired or invalid metadata exp.')
    elif ct == 'application/json':
        metadata = json_object(raw)
    else:
        raise FetchError('Issuer metadata must use application/json or application/jwt')
    if metadata.get('credential_issuer') != issuer:
        raise FetchError('credential_issuer does not match discovery identifier')
    https_identifier(metadata.get('credential_endpoint'))
    configs = metadata.get('credential_configurations_supported')
    if (draft == '1.0' or int(draft) >= 13) and (not isinstance(configs, dict) or not configs):
        raise FetchError('Missing credential_configurations_supported')
    for config_id in ids or []:
        cfg = (configs or {}).get(config_id)
        if not isinstance(cfg, dict):
            comments.append(f'ERROR: unknown credential_configuration_id {config_id}.')
            continue
        fmt = cfg.get('format')
        if fmt in ('dc+sd-jwt', 'vc+sd-jwt'):
            if not isinstance(cfg.get('vct'), str) or not cfg['vct']:
                comments.append(f'ERROR: {config_id}: SD-JWT vct missing.')
            if fmt == 'vc+sd-jwt':
                comments.append(f'WARNING: {config_id}: legacy vc+sd-jwt; final profile uses dc+sd-jwt.')
        elif fmt == 'mso_mdoc':
            if not isinstance(cfg.get('doctype'), str) or not cfg['doctype']:
                comments.append(f'ERROR: {config_id}: mdoc doctype missing.')
        elif not isinstance(fmt, str) or not fmt:
            comments.append(f'ERROR: {config_id}: format missing.')
        if cfg.get('proof_types_supported') is not None:
            proofs = cfg['proof_types_supported']
            if not isinstance(proofs, dict) or not proofs:
                comments.append(f'ERROR: {config_id}: invalid proof_types_supported.')
            else:
                for proof, details in proofs.items():
                    if not isinstance(details, dict) or not isinstance(details.get('proof_signing_alg_values_supported'), list) or not details['proof_signing_alg_values_supported']:
                        comments.append(f'ERROR: {config_id}: {proof} signing algorithms missing.')
    servers = metadata.get('authorization_servers', [issuer])
    if not isinstance(servers, list) or not servers or any(not isinstance(s,str) for s in servers):
        raise FetchError('Invalid authorization_servers')
    for server in servers:
        https_identifier(server)
    grants = offer.get('grants', {})
    if not isinstance(grants, dict):
        raise InputError('Invalid grants object')
    hints = []
    for grant, details in grants.items():
        if not isinstance(details, dict):
            raise InputError('Invalid grant details')
        hint = details.get('authorization_server')
        if hint:
            if hint not in servers or len(servers) < 2:
                raise InputError('Invalid grant authorization_server hint')
            hints.append(hint)
        if grant == 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
            if not isinstance(details.get('pre-authorized_code'),str) or not details['pre-authorized_code']:
                comments.append('ERROR: pre-authorized_code missing.')
            tx = details.get('tx_code')
            if tx is not None and (not isinstance(tx,dict) or tx.get('input_mode','numeric') not in ('numeric','text')):
                comments.append('ERROR: invalid tx_code.')
    # Audit every relevant AS rather than silently selecting the first one.
    selected = list(dict.fromkeys(hints)) if hints and all(isinstance(v,dict) and v.get('authorization_server') for v in grants.values()) else servers
    auth = []
    for server in selected:
        name = 'openid-configuration' if draft != '1.0' and int(draft) <= 11 else 'oauth-authorization-server'
        item = fetch_json(well_known(server, name, modern))
        if item.get('issuer') != server:
            raise FetchError('Authorization server issuer mismatch')
        for field in ('token_endpoint',):
            https_identifier(item.get(field))
        if 'authorization_code' in grants:
            https_identifier(item.get('authorization_endpoint'))
            if 'S256' not in item.get('code_challenge_methods_supported', []):
                comments.append(f'ERROR: {server}: authorization code requires PKCE S256 support.')
        for grant in grants:
            if grant not in item.get('grant_types_supported', ['authorization_code','implicit']):
                comments.append(f'ERROR: {server}: grant {grant} not advertised.')
        auth.append(item)
    for field in ('nonce_endpoint','deferred_credential_endpoint','notification_endpoint'):
        if field in metadata:
            https_identifier(metadata[field])
    comments.append('NOT_TESTED: metadata inspection does not execute authorization, nonce, token, credential or deferred issuance flows.')
    return json.dumps(offer), json.dumps(metadata), json.dumps(auth[0] if len(auth)==1 else auth), comments


def sd_jwt_checks(token):
    """Verify disclosure digests (including nested/array claims) and optional KB JWT.
    Issuer signature/trust is checked separately by the caller.
    """
    header, payload = decode_jwt(token.split('~')[0])
    errors, notes = [], []
    def error(message): errors.append('ERROR: '+message)
    if header.get('typ') not in ('dc+sd-jwt','vc+sd-jwt'):
        error('SD-JWT VC typ must be dc+sd-jwt (or legacy vc+sd-jwt).')
    if header.get('typ') == 'vc+sd-jwt': notes.append('WARNING: legacy vc+sd-jwt typ.')
    if header.get('alg') not in ALGORITHMS: error('Unsupported or forbidden issuer signing algorithm.')
    if header.get('x5c') is not None: notes.extend(certificate_checks(header['x5c']))
    if isinstance(header.get('jwk'),dict) and (header['jwk'].get('kty')=='oct' or any(k in header['jwk'] for k in ('d','p','q','k'))): error('Issuer jwk must be an asymmetric public key.')
    if 'cnf' in payload:
        cnf=payload['cnf']
        if not isinstance(cnf,dict) or not isinstance(cnf.get('jwk'),dict): error('Holder binding cnf.jwk must be a public JWK.')
        elif cnf['jwk'].get('kty')=='oct' or any(k in cnf['jwk'] for k in ('d','p','q','k')): error('Holder cnf.jwk must be asymmetric and public.')
    if not isinstance(payload.get('vct'), str) or not payload['vct']: error('vct is required.')
    if not isinstance(payload.get('iss'), str) or not payload['iss']: error('iss is required for SD-JWT VC.')
    now = time.time()
    for claim in ('iat','nbf','exp'):
        value = payload.get(claim)
        if value is not None and (isinstance(value,bool) or not isinstance(value,(int,float))): error(f'{claim} must be NumericDate.')
        elif value is not None:
            if claim == 'exp' and value <= now: error('Credential expired.')
            if claim in ('iat','nbf') and value > now + 60: error(f'{claim} is in the future.')
    hash_name = HASHES.get(payload.get('_sd_alg','sha-256'))
    if not hash_name:
        return ['ERROR: Unsupported _sd_alg.']
    def digest(text): return base64.urlsafe_b64encode(hashlib.new(hash_name,text.encode('ascii')).digest()).decode().rstrip('=')
    parts = token.split('~')
    kb = None
    if len(parts) == 1:
        error('SD-JWT without key binding must end with ~.')
        disclosures = []
    elif parts[-1]:
        if compact_jwt(parts[-1]): kb=parts[-1]; disclosures=parts[1:-1]
        else: error('Missing terminal ~ or invalid KB JWT.'); disclosures=parts[1:]
    else: disclosures=parts[1:-1]
    by_digest = {}
    for encoded in disclosures:
        try:
            obj = json.loads(decode_b64(encoded,True))
            if not isinstance(obj,list) or len(obj) not in (2,3) or not isinstance(obj[0],str) or not obj[0]:
                raise InputError('Disclosure must be [salt,value] or [salt,name,value]')
            if len(obj)==3 and (not isinstance(obj[1],str) or obj[1] in ('_sd','...')):
                raise InputError('Invalid disclosure claim name')
            hashed = digest(encoded)
            if hashed in by_digest: raise InputError('Duplicate disclosure')
            by_digest[hashed] = obj
        except (ValueError,TypeError) as exc: error(str(exc))
    seen, used = set(), set()
    def use(d, length):
        if not isinstance(d,str): error('Digest must be a string.'); return None
        if d in seen: error('Repeated digest in SD-JWT.'); return None
        seen.add(d)
        obj=by_digest.get(d)
        if obj is None: return None # undisclosed/decoy is allowed
        if len(obj)!=length: error('Disclosure object/array shape mismatch.'); return None
        used.add(d)
        return obj
    def walk(obj, depth=0):
        if depth>64: raise InputError('SD-JWT nesting exceeds limit')
        if isinstance(obj,dict):
            if depth and '_sd_alg' in obj: error('Nested _sd_alg is forbidden.')
            digests=obj.get('_sd',[])
            if not isinstance(digests,list): error('_sd must be an array.'); digests=[]
            names=set(obj)
            for d in digests:
                disclosure=use(d,3)
                if disclosure is not None:
                    if disclosure[1] in names: error('Disclosure overwrites an existing claim.')
                    names.add(disclosure[1]); walk(disclosure[2],depth+1)
            for key,value in obj.items():
                if key not in ('_sd','_sd_alg'): walk(value,depth+1)
        elif isinstance(obj,list):
            for value in obj:
                if isinstance(value,dict) and '...' in value:
                    if set(value)!={'...'}: error('Array digest placeholder has extra keys.')
                    disclosure=use(value['...'],2)
                    if disclosure is not None: walk(disclosure[1],depth+1)
                else: walk(value,depth+1)
    walk(payload)
    if set(by_digest)-used: error('Unreferenced or tampered disclosure digest.')
    if not errors: notes.append('PASS: disclosure digests, shapes and claim names verified (undisclosed claims allowed).')
    if kb:
        kh,kp=decode_jwt(kb)
        if kh.get('typ')!='kb+jwt': error('KB JWT typ must be kb+jwt.')
        if kp.get('sd_hash')!=digest(token[:token.rfind('~')+1]): error('KB JWT sd_hash mismatch.')
        if not isinstance(kp.get('nonce'),str) or not kp['nonce'] or not isinstance(kp.get('aud'),str) or not kp['aud']:
            error('KB JWT aud and nonce required.')
        if isinstance(kp.get('iat'),bool) or not isinstance(kp.get('iat'),(int,float)) or kp['iat']>now+60: error('KB JWT iat invalid.')
        try:
            key=payload.get('cnf',{}).get('jwk')
            if not isinstance(key,dict) or key.get('kty')=='oct' or any(k in key for k in ('d','p','q','k')): raise ValueError('Missing public holder cnf.jwk')
            verifier=jws.JWS(); verifier.allowed_algs=ALGORITHMS
            verifier.deserialize(kb); verifier.verify(jwk.JWK(**key))
            notes.append('PASS: KB JWT signature verified against issuer-bound cnf.jwk.')
        except Exception: error('KB JWT signature could not be verified against cnf.jwk.')
        notes.append('NOT_VERIFIED: expected verifier audience, nonce and freshness require presentation-session context.')
    else: notes.append('INFO: no KB JWT; normal for an issued credential stored in a wallet.')
    return errors+notes


def mdoc_checks(token):
    """MSO digests and validity for every document; COSE verification stays in analyzer."""
    obj=cbor_document(token)
    docs=obj.get('documents',[obj])
    notes=[]
    if 'documents' in obj and obj.get('status')!=0: notes.append('ERROR: DeviceResponse status is not zero.')
    if not isinstance(docs,list) or not docs: return ['ERROR: Empty or invalid documents.']
    for index,doc in enumerate(docs):
        prefix=f'Document {index}: '
        try:
            if not isinstance(doc,dict): raise InputError('Document must be a map')
            signed=doc.get('issuerSigned',doc)
            auth=signed['issuerAuth']
            if isinstance(auth,cbor2.CBORTag):
                if auth.tag!=18: raise InputError('Expected COSE tag 18')
                auth=auth.value
            if not isinstance(auth,list) or len(auth)!=4: raise InputError('Invalid issuerAuth COSE_Sign1')
            if not isinstance(auth[0],bytes) or not isinstance(auth[1],dict): raise InputError('Invalid COSE headers')
            protected=cbor2.loads(auth[0]) if auth[0] else {}
            if not isinstance(protected,dict) or protected.get(1) not in (-7,-35,-36,-8): raise InputError('Missing protected or unsupported COSE algorithm')
            if set(protected)&set(auth[1]): raise InputError('Duplicate protected/unprotected COSE header')
            mso_bytes=cbor2.loads(auth[2])
            if not isinstance(mso_bytes,cbor2.CBORTag) or mso_bytes.tag!=24 or not isinstance(mso_bytes.value,bytes): raise InputError('MSO must be tag 24 wrapping bytes')
            mso=cbor2.loads(mso_bytes.value)
            if mso.get('version')!='1.0': raise InputError('Unsupported MSO version')
            if not isinstance(mso.get('docType'),str) or not mso['docType']: raise InputError('Missing MSO docType')
            if 'docType' in doc and doc['docType']!=mso['docType']: raise InputError('docType does not match MSO')
            algorithm={'SHA-256':'sha256','SHA-384':'sha384','SHA-512':'sha512'}.get(mso.get('digestAlgorithm'))
            if not algorithm: raise InputError('Unsupported MSO digestAlgorithm')
            device_key=mso.get('deviceKeyInfo',{}).get('deviceKey')
            if not isinstance(device_key,dict): raise InputError('Missing MSO deviceKeyInfo.deviceKey')
            if -4 in device_key: raise InputError('MSO device key contains private key material')
            if device_key.get(1)==2:
                curve={1:ec.SECP256R1,2:ec.SECP384R1,3:ec.SECP521R1}.get(device_key.get(-1))
                if curve is None or not isinstance(device_key.get(-2),bytes) or not isinstance(device_key.get(-3),bytes): raise InputError('Unsupported or malformed MSO EC device key')
                ec.EllipticCurvePublicNumbers(int.from_bytes(device_key[-2],'big'),int.from_bytes(device_key[-3],'big'),curve()).public_key()
            elif device_key.get(1)==1 and device_key.get(-1)==6:
                ed25519.Ed25519PublicKey.from_public_bytes(device_key[-2])
            else: raise InputError('Unsupported MSO device key type')
            validity=mso['validityInfo']
            now=datetime.now(timezone.utc)
            dates={}
            for field in ('signed','validFrom','validUntil'):
                v=validity[field]
                if isinstance(v,cbor2.CBORTag): v=v.value
                if isinstance(v,str): v=datetime.fromisoformat(v.replace('Z','+00:00'))
                if not isinstance(v,datetime) or v.tzinfo is None: raise InputError('Invalid MSO validity timestamp')
                dates[field]=v
            if dates['signed']>dates['validFrom'] or dates['validFrom']>=dates['validUntil']: raise InputError('Inconsistent MSO validity interval')
            if not dates['validFrom']<=now<dates['validUntil']: raise InputError('MSO expired or not yet valid')
            namespaces=signed['nameSpaces']
            if not isinstance(namespaces,dict) or not namespaces: raise InputError('Missing issuer namespaces')
            count=0
            for ns,items in namespaces.items():
                if not isinstance(ns,str) or not isinstance(items,list): raise InputError('Invalid namespace')
                seen=set(); names=set()
                for wrapped in items:
                    if not isinstance(wrapped,cbor2.CBORTag) or wrapped.tag!=24 or not isinstance(wrapped.value,bytes): raise InputError('IssuerSignedItemBytes must be tag 24 wrapping bytes')
                    item=cbor2.loads(wrapped.value)
                    identifier=item.get('digestID')
                    if isinstance(identifier,bool) or not isinstance(identifier,int) or identifier<0 or identifier in seen: raise InputError('Invalid or duplicate digestID')
                    seen.add(identifier)
                    name=item.get('elementIdentifier')
                    if not isinstance(name,str) or name in names or 'elementValue' not in item: raise InputError('Invalid or duplicate elementIdentifier')
                    names.add(name)
                    if not isinstance(item.get('random'),bytes) or len(item['random'])<16: raise InputError('IssuerSignedItem random must contain at least 16 bytes')
                    expected=mso.get('valueDigests',{}).get(ns,{}).get(identifier)
                    actual=hashlib.new(algorithm,cbor2.dumps(wrapped)).digest()
                    if not isinstance(expected,bytes) or actual!=expected: raise InputError('IssuerSignedItem digest does not match MSO')
                    count+=1
            notes.append(f'PASS: {prefix}{count} item digests, docType and MSO validity checked.')
            certs=protected.get(33,auth[1].get(33))
            certs=[certs] if isinstance(certs,bytes) else certs
            if not isinstance(certs,list) or not certs: raise InputError('Missing x5chain')
            chain=[x509.load_der_x509_certificate(c) for c in certs]
            for cert in chain:
                if not cert.not_valid_before_utc<=now<=cert.not_valid_after_utc: raise InputError('x5chain certificate expired or not yet valid')
            for leaf,parent in zip(chain,chain[1:]):
                leaf.verify_directly_issued_by(parent)
                constraints=parent.extensions.get_extension_for_class(x509.BasicConstraints).value
                if not constraints.ca: raise InputError('Issuer certificate is not a CA')
            notes.append('NOT_VERIFIED: '+prefix+'IACA trust anchor and revocation require a configured trust policy; an embedded chain alone does not establish trust.')
            if 'deviceSigned' in doc: notes.append('NOT_VERIFIED: '+prefix+'device authentication requires SessionTranscript and the MSO device key; it cannot be validated from an issued credential alone.')
        except Exception as exc:
            notes.append(f'ERROR: {prefix}{exc}')
    return notes


def configuration_assessment(offer, metadata, authorization_servers, comments=()):
    """Metadata-only verdicts; never infer runtime conformance from advertised support."""
    auth = authorization_servers if isinstance(authorization_servers,list) else [authorization_servers]
    base_issuer=metadata_findings(metadata); base_as=[]; haip_issuer=[]; haip_as=[]; unknown=[]
    def issue(bucket, condition, message):
        if not condition: bucket.append(message)
    issue(base_issuer, isinstance(metadata.get('credential_configurations_supported'),dict) and bool(metadata['credential_configurations_supported']), 'credential_configurations_supported missing/invalid')
    try: https_identifier(metadata.get('credential_issuer')); https_identifier(metadata.get('credential_endpoint'))
    except InputError as exc: base_issuer.append(str(exc))
    configs=metadata.get('credential_configurations_supported',{})
    configs=configs if isinstance(configs,dict) else {}
    for cid,cfg in configs.items():
        if not isinstance(cfg,dict): base_issuer.append(f'{cid}: invalid configuration'); continue
        fmt=cfg.get('format')
        issue(base_issuer, isinstance(fmt,str) and bool(fmt), f'{cid}: missing format')
        if fmt in ('dc+sd-jwt','vc+sd-jwt'): issue(base_issuer, isinstance(cfg.get('vct'),str) and bool(cfg['vct']), f'{cid}: missing vct')
        if fmt=='mso_mdoc': issue(base_issuer, isinstance(cfg.get('doctype'),str) and bool(cfg['doctype']), f'{cid}: missing doctype')
        issue(haip_issuer, isinstance(cfg.get('scope'),str) and bool(cfg['scope']), f'{cid}: HAIP requires a scope')
        if cfg.get('cryptographic_binding_methods_supported'):
            issue(haip_issuer, bool(metadata.get('nonce_endpoint')), f'{cid}: HAIP holder binding requires nonce_endpoint')
        # HAIP requires at least one applicable format, not exclusively these formats.
        if fmt in ('dc+sd-jwt','mso_mdoc'):
            proofs = cfg.get('proof_types_supported', {})
            if not isinstance(proofs,dict):
                base_issuer.append(f'{cid}: invalid proof_types_supported'); proofs={}
            for proof,details in proofs.items():
                if isinstance(details,dict): issue(haip_issuer, 'ES256' in details.get('proof_signing_alg_values_supported',[]), f'{cid}/{proof}: HAIP ES256 proof support missing')
    issue(haip_issuer, any(isinstance(c,dict) and c.get('format') in ('dc+sd-jwt','mso_mdoc') for c in configs.values()), 'HAIP requires dc+sd-jwt or mso_mdoc')
    ids=offer.get('credential_configuration_ids',[])
    issue(base_issuer, isinstance(ids,list) and bool(ids) and all(isinstance(i,str) and i in configs for i in ids), 'offer references missing/unknown credential configurations')
    grants=offer.get('grants',{})
    for server in auth:
        if not isinstance(server,dict): base_as.append('invalid AS metadata'); continue
        label=server.get('issuer','AS')
        try: https_identifier(server.get('issuer')); https_identifier(server.get('token_endpoint'))
        except InputError as exc: base_as.append(f'{label}: {exc}')
        supported=server.get('grant_types_supported',['authorization_code','implicit'])
        for grant in grants:
            issue(base_as, grant in supported, f'{label}: grant {grant} not supported')
        if 'authorization_code' in supported:
            try: https_identifier(server.get('authorization_endpoint'))
            except InputError as exc: base_as.append(f'{label}: {exc}')
            issue(base_as, 'S256' in server.get('code_challenge_methods_supported',[]), f'{label}: PKCE S256 missing for authorization code')
        issue(haip_as, 'authorization_code' in supported, f'{label}: HAIP requires authorization code support')
        try: https_identifier(server.get('pushed_authorization_request_endpoint'))
        except InputError: haip_as.append(f'{label}: HAIP requires an HTTPS PAR endpoint')
        issue(haip_as, server.get('require_pushed_authorization_requests') is True, f'{label}: FAPI PAR enforcement not advertised')
        issue(haip_as, server.get('authorization_response_iss_parameter_supported') is True, f'{label}: authorization response iss support missing')
        issue(haip_as, 'ES256' in server.get('dpop_signing_alg_values_supported',[]), f'{label}: HAIP DPoP ES256 support missing')
        methods=server.get('token_endpoint_auth_methods_supported',['client_secret_basic'])
        issue(haip_as, isinstance(methods,list) and bool(methods) and 'none' not in methods and any(m in ('private_key_jwt','tls_client_auth','self_signed_tls_client_auth','attest_jwt_client_auth') for m in methods), f'{label}: HAIP requires client authentication')
    for c in comments:
        if c.startswith('ERROR:'): base_issuer.append(c)
        if c.startswith('NOT_VERIFIED:'): unknown.append(c)
    if not auth: base_as.append('No AS was inspected')
    def verdict(issuer_errors, as_errors):
        failures=list(dict.fromkeys(issuer_errors+as_errors))
        return {'status':'NON_COMPATIBLE' if failures else ('INDETERMINE' if unknown else 'COMPATIBLE_METADATA'), 'issuer':'NON_COMPATIBLE' if issuer_errors else 'AUCUNE_INCOMPATIBILITE_DETECTEE', 'authorization_server':'NON_COMPATIBLE' if as_errors else 'AUCUNE_INCOMPATIBILITE_DETECTEE', 'reasons':failures, 'not_verified':list(dict.fromkeys(unknown)), 'scope':'Configuration statique uniquement; les flux réels ne sont pas certifiés.'}
    return {'OIDC4VCI_1_0':verdict(base_issuer,base_as), 'HAIP_1_0':verdict(base_issuer+haip_issuer,base_as+haip_as)}


def assessment_markdown(assessment):
    lines=['## Avis de compatibilité de la configuration']
    for name,item in assessment.items():
        lines += [f"### {name.replace('_',' ')} : {item['status']}", f"Issuer : {item['issuer']}. AS : {item['authorization_server']}."]
        lines += ['- '+r for r in item['reasons']]
        lines += ['- Non vérifié : '+r for r in item['not_verified']]
        lines.append(item['scope'])
    lines.append('COMPATIBLE_METADATA signifie que les contrôles statiques implémentés ne détectent pas de blocage; cela ne certifie pas une conformité complète.')
    return '\n'.join(lines)+'\n\n'


def update_counter(path='openai_counter.json'):
    """Best-effort atomic counter; diagnostics never fail due to telemetry."""
    try:
        with open(path, 'r+') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            counter=json.load(f)
            counter['request_number'] += 1
            f.seek(0); json.dump(counter,f); f.truncate()
    except (OSError, ValueError, KeyError, TypeError):
        logging.warning('AI usage counter unavailable')
    return True


def certificate_checks(encoded_chain):
    """Certificate structure, validity and supplied chain signatures, without trust inference."""
    notes=[]
    try:
        if not isinstance(encoded_chain,list) or not encoded_chain:
            raise InputError('x5c must be a non-empty array')
        certs=[x509.load_der_x509_certificate(decode_b64(c)) for c in encoded_chain]
        now=datetime.now(timezone.utc)
        for cert in certs:
            if not cert.not_valid_before_utc<=now<=cert.not_valid_after_utc:
                raise InputError('Certificate expired or not yet valid')
        for child,parent in zip(certs,certs[1:]):
            child.verify_directly_issued_by(parent)
            if not parent.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise InputError('Certificate issuer is not a CA')
        notes.append('PASS: supplied certificate validity and chain signatures checked.')
    except Exception as exc:
        notes.append('ERROR: x5c: '+str(exc))
    notes.append('NOT_VERIFIED: embedded certificates do not establish trust-anchor authorization or revocation status.')
    return notes


def metadata_findings(metadata):
    """Final 1.0 metadata schema checks beyond fields needed for discovery."""
    errors=[]
    def error(message): errors.append(message)
    def strings(value): return isinstance(value,list) and bool(value) and all(isinstance(v,str) and bool(v) for v in value)
    batch=metadata.get('batch_credential_issuance')
    if batch is not None:
        size=batch.get('batch_size') if isinstance(batch,dict) else None
        if isinstance(size,bool) or not isinstance(size,int) or size<2:
            error('batch_credential_issuance.batch_size must be an integer >= 2')
    for field in ('credential_request_encryption','credential_response_encryption'):
        obj=metadata.get(field)
        if obj is None: continue
        if not isinstance(obj,dict): error(field+' must be an object'); continue
        if not isinstance(obj.get('encryption_required'),bool): error(field+'.encryption_required must be boolean')
        if not strings(obj.get('enc_values_supported')): error(field+'.enc_values_supported must be a nonempty string array')
        if field=='credential_response_encryption' and not strings(obj.get('alg_values_supported')):
            error(field+'.alg_values_supported must be a nonempty string array')
        if field=='credential_request_encryption':
            keys=obj.get('jwks',{}).get('keys') if isinstance(obj.get('jwks'),dict) else None
            if not isinstance(keys,list) or not keys: error(field+'.jwks.keys missing')
            else:
                ids=[]
                for key in keys:
                    if not isinstance(key,dict) or not isinstance(key.get('kid'),str) or not key['kid'] or key.get('kty')=='oct' or any(k in key for k in ('d','p','q','k')):
                        error(field+'.jwks must contain public asymmetric keys with kid')
                    else: ids.append(key['kid'])
                if len(set(ids))!=len(ids): error(field+'.jwks contains duplicate kid')
    configs=metadata.get('credential_configurations_supported',{})
    if isinstance(configs,dict):
        for cid,cfg in configs.items():
            if not isinstance(cfg,dict): continue
            if 'scope' in cfg and (not isinstance(cfg['scope'],str) or not cfg['scope']): error(f'{cid}: invalid scope')
            if 'cryptographic_binding_methods_supported' in cfg and not strings(cfg['cryptographic_binding_methods_supported']): error(f'{cid}: invalid binding methods')
            if 'credential_signing_alg_values_supported' in cfg:
                algs=cfg['credential_signing_alg_values_supported']
                if not isinstance(algs,list) or not algs or any(isinstance(a,bool) or not isinstance(a,(int,str)) for a in algs): error(f'{cid}: invalid signing algorithms')
            proofs=cfg.get('proof_types_supported')
            if proofs is not None:
                if not isinstance(proofs,dict) or not proofs: error(f'{cid}: invalid proof_types_supported')
                else:
                    for proof,details in proofs.items():
                        if not isinstance(details,dict) or not strings(details.get('proof_signing_alg_values_supported')):
                            error(f'{cid}/{proof}: invalid proof signing algorithms')
    return errors
