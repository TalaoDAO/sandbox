"""Offline regression tests: real wallet routes/analyzers, generated signed credentials.
External HTTP and GPT are mocked; no publication or notification is sent.
"""
import ast
import asyncio
import base64
import copy
import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlencode
from unittest.mock import Mock

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify, request
from jwcrypto import jwk, jws

from ai import wallet_validation as val
from ai import ai_agent_for_vc as vc_agent, ai_agent_for_qrcode as qr_agent

ROOT=Path(__file__).resolve().parents[1]

def encode(raw): return base64.urlsafe_b64encode(raw).decode().rstrip('=')
def disclosure(value): return encode(json.dumps(value,separators=(',',':')).encode())
def digest(encoded): return encode(hashlib.sha256(encoded.encode()).digest())
def sign(payload,key,typ='dc+sd-jwt',extra=None):
    token=jws.JWS(json.dumps(payload).encode())
    header={'alg':'ES256','typ':typ, **(extra or {})}
    token.add_signature(key,protected=json.dumps(header))
    return token.serialize(compact=True)

@pytest.fixture(autouse=True)
def no_external_side_effects(monkeypatch):
    monkeypatch.setattr(val.requests,'get',Mock(side_effect=AssertionError('Unexpected external GET')))
    monkeypatch.setattr(val.requests,'post',Mock(side_effect=AssertionError('Unexpected external POST')))
    for agent in (qr_agent,vc_agent):
        monkeypatch.setattr(agent,'counter_update',Mock())
        monkeypatch.setattr(agent,'store_report',Mock())
        monkeypatch.setattr(agent,'get_llm_client',Mock(return_value=SimpleNamespace(invoke=Mock(return_value=SimpleNamespace(content='GPT report')))))

@pytest.fixture
def signed_sd():
    key=jwk.JWK.generate(kty='EC',crv='P-256')
    d=disclosure(['a-long-random-salt','given_name','Alice'])
    payload={'iss':'urn:example:issuer','vct':'urn:example:pid','iat':int(time.time())-10,'exp':int(time.time())+3600,'_sd':[digest(d)]}
    extra={'jwk':json.loads(key.export_public())}
    return key,payload,d,extra

def checks(payload,key,ds,extra):
    return val.sd_jwt_checks(sign(payload,key,extra=extra)+'~'+'~'.join(ds)+('~' if ds else ''))
def no_error(notes): assert not any(n.startswith('ERROR:') for n in notes), notes

def test_sd_valid_disclosures(signed_sd):
    key,p,d,e=signed_sd; no_error(checks(p,key,[d],e))

def test_sd_undisclosed_allowed(signed_sd):
    key,p,d,e=signed_sd; no_error(checks(p,key,[],e))

@pytest.mark.parametrize('mutation', ['tampered','duplicate','collision','wrong_shape','expired','future','bad_hash','none_alg','nested_alg','duplicate_digest','invalid_salt'])
def test_sd_negative(signed_sd,mutation):
    key,p,d,e=signed_sd; ds=[d]
    if mutation=='tampered': ds=[disclosure(['a-long-random-salt','given_name','Mallory'])]
    if mutation=='duplicate': ds=[d,d]
    if mutation=='collision': p['given_name']='Bob'
    if mutation=='wrong_shape': ds=[disclosure(['salt','value'])]; p['_sd']=[digest(ds[0])]
    if mutation=='expired': p['exp']=1
    if mutation=='future': p['nbf']=int(time.time())+1000
    if mutation=='bad_hash': p['_sd_alg']='md5'
    if mutation=='none_alg':
        tok=encode(b'{"alg":"none","typ":"dc+sd-jwt"}')+'.'+encode(json.dumps(p).encode())+'.c2ln~'
        assert any('algorithm' in n for n in val.sd_jwt_checks(tok)); return
    if mutation=='nested_alg': p['address']={'_sd_alg':'sha-256'}
    if mutation=='duplicate_digest': p['_sd']*=2
    if mutation=='invalid_salt': ds=[disclosure([1,'given_name','Alice'])]; p['_sd']=[digest(ds[0])]
    assert any(n.startswith('ERROR:') for n in checks(p,key,ds,e))

def test_sd_nested_and_array(signed_sd):
    key,p,d,e=signed_sd
    array=disclosure(['salt-array','US'])
    nested=disclosure(['salt-address','address',{'country_codes':[{'...':digest(array)}]}])
    p['_sd']=[digest(nested)]
    no_error(checks(p,key,[array,nested],e))

@pytest.mark.parametrize('mutation',['valid','sd_hash','signature','typ','nonce'])
def test_sd_key_binding(signed_sd,mutation):
    key,p,d,e=signed_sd; holder=jwk.JWK.generate(kty='EC',crv='P-256')
    p['cnf']={'jwk':json.loads(holder.export_public())}
    prefix=sign(p,key,extra=e)+'~'+d+'~'
    kb={'aud':'https://verifier.example','nonce':'test-nonce','iat':int(time.time()),'sd_hash':digest(prefix)}
    if mutation=='sd_hash': kb['sd_hash']='wrong'
    if mutation=='nonce': del kb['nonce']
    kbjwt=sign(kb,jwk.JWK.generate(kty='EC',crv='P-256') if mutation=='signature' else holder,typ='wrong' if mutation=='typ' else 'kb+jwt')
    notes=val.sd_jwt_checks(prefix+kbjwt)
    if mutation=='valid': no_error(notes); assert any('signature verified' in n for n in notes)
    else: assert any(n.startswith('ERROR:') for n in notes)

def test_sd_real_analyzer_preserves_signature_failure(signed_sd):
    key,p,d,e=signed_sd
    token=sign(p,jwk.JWK.generate(kty='EC',crv='P-256'),extra=e)+'~'+d+'~'
    result=vc_agent.analyze_sd_jwt_vc(token,'13','test','pro','openai')
    assert 'signature verification with jwk in header failed' in result
    assert 'issuer authorization/trust' in result

def test_sd_real_analyzer_success(signed_sd):
    key,p,d,e=signed_sd
    result=asyncio.run(vc_agent.process_vc_format(sign(p,key,extra=e)+'~'+d+'~','13','1.1','test','pro','openai'))
    assert 'Disclosures' not in result or 'ERROR:' not in result
    assert 'correctly signed with jwk' in result

@pytest.fixture
def mdoc():
    private=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Test DS')])
    now=datetime.now(timezone.utc).replace(microsecond=0)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(1)
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).sign(private,hashes.SHA256()))
    item=cbor2.CBORTag(24,cbor2.dumps({'digestID':0,'random':b'0123456789abcdef','elementIdentifier':'given_name','elementValue':'Alice'}))
    point=private.public_key().public_numbers()
    mso={'version':'1.0','digestAlgorithm':'SHA-256','docType':'org.iso.18013.5.1.mDL','deviceKeyInfo':{'deviceKey':{1:2,-1:1,-2:point.x.to_bytes(32,'big'),-3:point.y.to_bytes(32,'big')}},'validityInfo':{'signed':now-timedelta(hours=1),'validFrom':now-timedelta(minutes=30),'validUntil':now+timedelta(hours=1)},'valueDigests':{'org.iso.18013.5.1':{0:hashlib.sha256(cbor2.dumps(item)).digest()}}}
    def build(mso_override=None, item_override=None, alg=-7):
        payload=cbor2.dumps(cbor2.CBORTag(24,cbor2.dumps(mso_override or mso)))
        protected=cbor2.dumps({1:alg})
        signature=private.sign(cbor2.dumps(['Signature1',protected,b'',payload]),ec.ECDSA(hashes.SHA256()))
        r,s=decode_dss_signature(signature)
        auth=[protected,{33:cert.public_bytes(serialization.Encoding.DER)},payload,r.to_bytes(32,'big')+s.to_bytes(32,'big')]
        return {'nameSpaces':{'org.iso.18013.5.1':[item_override or item]},'issuerAuth':cbor2.CBORTag(18,auth)}
    return mso,item,build

def mdoc_token(obj): return encode(cbor2.dumps(obj))
@pytest.mark.parametrize('wrapper',['issuer','document','device','multiple'])
def test_mdoc_all_shapes(mdoc,wrapper):
    _,_,build=mdoc; obj=build()
    if wrapper=='document': obj={'docType':'org.iso.18013.5.1.mDL','issuerSigned':obj}
    if wrapper in ('device','multiple'): obj={'version':'1.0','status':0,'documents':[{'docType':'org.iso.18013.5.1.mDL','issuerSigned':obj}]*(2 if wrapper=='multiple' else 1)}
    token=mdoc_token(obj)
    assert val.detect_format(token)=='mdoc'
    no_error(val.mdoc_checks(token))
    result=asyncio.run(vc_agent.process_vc_format(token,'13','1.1','test','pro','openai'))
    assert 'COSE signature verified successfully' in result
    assert result.count('COSE signature verified successfully')==(2 if wrapper=='multiple' else 1)

@pytest.mark.parametrize('mutation',['item','digest','expired','doctype','alg','signature','trailing','duplicate'])
def test_mdoc_negative(mdoc,mutation):
    mso,item,build=mdoc; mso=copy.deepcopy(mso)
    if mutation=='digest': mso['valueDigests']['org.iso.18013.5.1'][0]=b'x'*32
    if mutation=='expired': mso['validityInfo']['validUntil']=datetime.now(timezone.utc)-timedelta(minutes=1)
    obj=build(mso)
    if mutation=='item': obj['nameSpaces']['org.iso.18013.5.1'][0]=cbor2.CBORTag(24,cbor2.dumps({**cbor2.loads(item.value),'elementValue':'Mallory'}))
    if mutation=='doctype': obj={'docType':'wrong','issuerSigned':obj}
    if mutation=='alg': obj['issuerAuth'].value[0]=cbor2.dumps({1:-35})
    if mutation=='signature': obj['issuerAuth'].value[3]=b'x'*64
    if mutation=='duplicate': obj['nameSpaces']['org.iso.18013.5.1']*=2
    token=mdoc_token(obj)
    if mutation=='trailing':
        with pytest.raises(val.InputError): val.detect_format(encode(cbor2.dumps(obj)+b'x'))
        return
    result=vc_agent.analyze_mdoc(token,'18013-5','test','pro','openai')
    assert 'ERROR:' in result or 'Error:' in result

@pytest.mark.parametrize('value',['%%%!!!','', 'a.b.c', '[1,2]', 'null','eyJhbGciOiJub25lIn0.e30.'])
def test_invalid_format(value):
    with pytest.raises(val.InputError): val.detect_format(value)
@pytest.mark.parametrize('context',['https://www.w3.org/2018/credentials/v1','https://www.w3.org/ns/credentials/v2'])
def test_jsonld_not_misclassified(context):
    assert val.detect_format(json.dumps({'@context':[context],'type':['VerifiableCredential']}))=='jsonld'

@pytest.fixture
def metadata():
    issuer='https://issuer.example/tenant'; as1='https://auth.example/one'; as2='https://auth.example/two'
    offer={'credential_issuer':issuer,'credential_configuration_ids':['pid'],'grants':{'authorization_code':{'authorization_server':as2}}}
    meta={'credential_issuer':issuer,'credential_endpoint':issuer+'/credential','nonce_endpoint':issuer+'/nonce','authorization_servers':[as1,as2], 'credential_configurations_supported':{'pid':{'format':'dc+sd-jwt','vct':'urn:pid','scope':'pid','cryptographic_binding_methods_supported':['jwk'],'proof_types_supported':{'jwt':{'proof_signing_alg_values_supported':['ES256']}}}}}
    auth={'issuer':as2,'token_endpoint':as2+'/token','authorization_endpoint':as2+'/authorize','grant_types_supported':['authorization_code'],'code_challenge_methods_supported':['S256'],'pushed_authorization_request_endpoint':as2+'/par','require_pushed_authorization_requests':True,'authorization_response_iss_parameter_supported':True,'dpop_signing_alg_values_supported':['ES256'],'token_endpoint_auth_methods_supported':['attest_jwt_client_auth']}
    return offer,meta,auth

def mock_discovery(monkeypatch,offer,meta,auth):
    urls=[]
    def fetch(url,accept='application/json'):
        urls.append(url)
        obj=offer if url=='https://offer.example/value' else auth if 'oauth-authorization-server' in url else meta
        return json.dumps(obj).encode(),'application/json'
    monkeypatch.setattr(val,'fetch',fetch)
    return urls
@pytest.mark.parametrize('version',['1.0','final','1_0','18'])
@pytest.mark.parametrize('by_reference',[True,False])
def test_discovery_final_and_path(monkeypatch,metadata,version,by_reference):
    offer,meta,auth=metadata; urls=mock_discovery(monkeypatch,*metadata)
    params={'credential_offer_uri':'https://offer.example/value'} if by_reference else {'credential_offer':json.dumps(offer)}
    result=qr_agent.get_issuer_data('openid-credential-offer://?'+urlencode(params),version)
    assert 'https://issuer.example/.well-known/openid-credential-issuer/tenant' in urls
    assert urls[-1]=='https://auth.example/.well-known/oauth-authorization-server/two'
    assert json.loads(result[2])==auth

def test_discovery_preauth_selects_as(monkeypatch,metadata):
    offer,meta,auth=metadata
    offer['grants']={'urn:ietf:params:oauth:grant-type:pre-authorized_code':{'pre-authorized_code':'synthetic-code','authorization_server':auth['issuer']}}
    auth['grant_types_supported']=list(offer['grants'])
    urls=mock_discovery(monkeypatch,*metadata)
    qr_agent.get_issuer_data('haip-vci://?'+urlencode({'credential_offer':json.dumps(offer)}),'1.0')
    assert urls[-1].endswith('/two')

@pytest.mark.parametrize('mutation',['issuer','ids','hint','metadata_issuer','as_issuer','dual_offer'])
def test_discovery_invalid(monkeypatch,metadata,mutation):
    offer,meta,auth=metadata
    if mutation=='issuer': offer['credential_issuer']='http://localhost'
    if mutation=='ids': offer['credential_configuration_ids']=['pid','pid']
    if mutation=='hint': offer['grants']['authorization_code']['authorization_server']='https://evil.example'
    if mutation=='metadata_issuer': meta['credential_issuer']='https://different.example'
    if mutation=='as_issuer': auth['issuer']='https://different.example'
    mock_discovery(monkeypatch,*metadata)
    params={'credential_offer':json.dumps(offer)}
    if mutation=='dual_offer': params['credential_offer_uri']='https://offer.example/value'
    with pytest.raises((val.InputError,val.FetchError)):
        qr_agent.get_issuer_data('openid-credential-offer://?'+urlencode(params),'1.0')

@pytest.mark.parametrize('mutation',['compatible','scope','par','dpop','pkce','code','nonce','legacy','unknown_config'])
def test_verdicts(metadata,mutation):
    offer,meta,auth=metadata
    if mutation=='scope': del meta['credential_configurations_supported']['pid']['scope']
    if mutation=='par': del auth['pushed_authorization_request_endpoint']
    if mutation=='dpop': auth['dpop_signing_alg_values_supported']=[]
    if mutation=='pkce': auth['code_challenge_methods_supported']=[]
    if mutation=='code': auth['grant_types_supported']=['urn:ietf:params:oauth:grant-type:pre-authorized_code']
    if mutation=='nonce': del meta['nonce_endpoint']
    if mutation=='legacy': meta['credential_configurations_supported']['pid']['format']='vc+sd-jwt'
    if mutation=='unknown_config': offer['credential_configuration_ids']=['other']
    result=val.configuration_assessment(offer,meta,auth)
    if mutation=='compatible': assert result['HAIP_1_0']['status']=='COMPATIBLE_METADATA'
    else: assert result['HAIP_1_0']['status']=='NON_COMPATIBLE'
    if mutation in ('scope','par','dpop','nonce','legacy'): assert result['OIDC4VCI_1_0']['status']=='COMPATIBLE_METADATA'

def test_signed_metadata_does_not_infer_trust(metadata):
    verdict=val.configuration_assessment(*metadata,comments=['NOT_VERIFIED: signer trust'])
    assert verdict['OIDC4VCI_1_0']['status']=='INDETERMINE'

def test_issuer_report_contains_verdicts(monkeypatch,metadata):
    offer,meta,auth=metadata; mock_discovery(monkeypatch,*metadata)
    report=qr_agent.analyze_issuer_qrcode('openid-credential-offer://?'+urlencode({'credential_offer':json.dumps(offer)}),'1.0','','test','pro','openai')
    assert 'OIDC4VCI 1.0 : Compatible based on metadata' in report
    assert 'HAIP 1.0 : Compatible based on metadata' in report
    assert 'GPT report' in report
    prompt=qr_agent.get_llm_client.return_value.invoke.call_args.args[0]
    assert 'Final when version is 1.0' in prompt[0]['content']
    assert 'Draft 13' not in prompt[0]['content']

@pytest.mark.parametrize('url',['http://issuer.example','https://127.0.0.1','https://[::1]','https://user:pass@example.com','https://localhost'])
def test_private_and_invalid_urls(monkeypatch,url):
    monkeypatch.setattr(val.socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',('127.0.0.1',443))])
    with pytest.raises(val.InputError): val.public_url(url)

def test_fetch_rejects_http404(monkeypatch):
    monkeypatch.setattr(val,'public_url',lambda u:None)
    response=Mock(status_code=404)
    response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
    monkeypatch.setattr(val.requests,'get',Mock(return_value=response))
    with pytest.raises(val.FetchError,match='HTTP 404'): val.fetch('https://issuer.example')

def test_fetch_redirect_checks_private_target(monkeypatch):
    monkeypatch.setattr(val.socket,'getaddrinfo',lambda host,*a,**k:[(2,1,6,'',('127.0.0.1' if host=='localhost' else '8.8.8.8',443))])
    response=Mock(status_code=302,headers={'Location':'https://localhost/admin'})
    response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
    mock=Mock(return_value=response);monkeypatch.setattr(val.requests,'get',mock)
    with pytest.raises(val.InputError): val.fetch('https://issuer.example')
    assert mock.call_count==1

@pytest.fixture
def client():
    tree=ast.parse((ROOT/'main.py').read_text())
    funcs=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in ('qrcode_wallet','vc_wallet')]
    for n in funcs: n.decorator_list=[]
    env=dict(request=request,jsonify=jsonify,base64=base64,logging=logging,ai_api_keys=['test'],ai_agent_for_qrcode=qr_agent,ai_agent_for_vc=vc_agent,ai_validation=val)
    exec(compile(ast.Module(body=funcs,type_ignores=[]),'main.py','exec'),env)
    app=Flask('test-ai')
    app.add_url_rule('/ai/wallet/qrcode',view_func=env['qrcode_wallet'],methods=['POST'])
    app.add_url_rule('/ai/wallet/vc',view_func=lambda:asyncio.run(env['vc_wallet']()),methods=['POST'])
    return app.test_client()

@pytest.fixture
def website_client():
    from flask import render_template
    tree = ast.parse((ROOT / 'main.py').read_text())
    names = ('qrcode', 'vc', '_ai_input_error_response')
    funcs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in names]
    for node in funcs:
        node.decorator_list = []
    env = dict(request=request, jsonify=jsonify, render_template=render_template,
               ai_validation=val, ai_agent_for_qrcode=qr_agent,
               ai_agent_for_vc=vc_agent, logging=logging)
    exec(compile(ast.Module(body=funcs, type_ignores=[]), 'main.py', 'exec'), env)
    app = Flask('test-ai-website', template_folder=str(ROOT / 'templates'))
    app.add_url_rule('/ai/qrcode', view_func=env['qrcode'], methods=['POST'])
    app.add_url_rule('/ai/vc', view_func=lambda: asyncio.run(env['vc']()), methods=['POST'])
    return app.test_client()

@pytest.mark.parametrize('route,field', [('vc', 'vc'), ('qrcode', 'qrcode')])
@pytest.mark.parametrize('value', [None, '', '   ', '1', "1'", '%%%!!!'])
@pytest.mark.parametrize('outfmt', ['text', 'json'])
def test_website_invalid_input_no_llm(website_client, route, field, value, outfmt):
    data = {'outfmt': outfmt}
    if value is not None:
        data[field] = value
    response = website_client.post('/ai/' + route, data=data)
    assert response.status_code == 400
    if outfmt == 'json':
        assert response.json['error']
    else:
        assert b'Error:' in response.data
    for agent in (qr_agent, vc_agent):
        agent.get_llm_client.assert_not_called()
        agent.counter_update.assert_not_called()
        agent.store_report.assert_not_called()

@pytest.mark.parametrize('parameter', ['credential_offer_uri', 'credential_offer', 'request_uri', 'request', 'response_mode'])
def test_qrcode_protocol_input_preserved(parameter):
    value = 'openid://?' + urlencode({parameter: 'test'})
    assert val.validate_qrcode_input(value) == value

def test_website_vc_error_is_escaped(website_client, monkeypatch):
    async def invalid(*args):
        raise val.InputError('Invalid claim: <script>')
    monkeypatch.setattr(vc_agent, 'process_vc_format', invalid)
    response = website_client.post('/ai/vc', data={'vc': '{"<script>":1,"<script>":2}'})
    assert response.status_code == 400
    assert b'&lt;script&gt;' in response.data
    assert b'Invalid claim: <script>' not in response.data

@pytest.mark.parametrize('route,field',[('vc','vc'),('qrcode','qrcode')])
@pytest.mark.parametrize('scenario',['auth','missing','base64','empty','utf8'])
def test_wallet_transport(client,route,field,scenario):
    data={} if scenario=='missing' else {field:{'base64':'%%%!!!','empty':'IA==','utf8':'/w=='}.get(scenario,'dGVzdA==')}
    response=client.post('/ai/wallet/'+route,data=data,headers={} if scenario=='auth' else {'Api-Key':'test'})
    assert response.status_code==(403 if scenario=='auth' else 400)

def test_wallet_vc_real_sdjwt(client,signed_sd):
    key,p,d,e=signed_sd; token=sign(p,key,extra=e)+'~'+d+'~'
    response=client.post('/ai/wallet/vc',data={'vc':base64.b64encode(token.encode()).decode()},headers={'Api-Key':'test'})
    assert response.status_code==200
    assert 'correctly signed with jwk' in base64.b64decode(response.data).decode()

def test_wallet_qrcode_real_discovery(client,monkeypatch,metadata):
    mock_discovery(monkeypatch,*metadata)
    uri='openid-credential-offer://?'+urlencode({'credential_offer':json.dumps(metadata[0])})
    response=client.post('/ai/wallet/qrcode',data={'qrcode':base64.b64encode(uri.encode()).decode()},headers={'Api-Key':'test'})
    assert response.status_code==200
    assert 'HAIP 1.0' in base64.b64decode(response.data).decode()
    assert qr_agent.get_llm_client.call_args.args==('pro','openai')

@pytest.mark.parametrize('field,value',[
    ('batch_credential_issuance',{'batch_size':1}),
    ('batch_credential_issuance',{'batch_size':True}),
    ('credential_response_encryption',{'enc_values_supported':[]}),
    ('credential_request_encryption',{'encryption_required':True,'enc_values_supported':['A256GCM'],'jwks':{'keys':[]}}),
])
def test_invalid_optional_metadata_is_a_blocker(metadata,field,value):
    offer,meta,auth=metadata;meta[field]=value
    result=val.configuration_assessment(offer,meta,auth)
    assert result['OIDC4VCI_1_0']['status']=='NON_COMPATIBLE'

@pytest.mark.parametrize('tamper',[False,True])
def test_signed_metadata_signature_and_trust(monkeypatch,metadata,tamper):
    offer,meta,auth=metadata
    private=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Test metadata signer')])
    now=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(22)
          .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).sign(private,hashes.SHA256()))
    key=jwk.JWK.from_pyca(private)
    if tamper: key=jwk.JWK.generate(kty='EC',crv='P-256')
    signed=sign({**meta,'sub':meta['credential_issuer'],'iat':int(time.time())},key,typ='openidvci-issuer-metadata+jwt',extra={'x5c':[base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]})
    def fetch(url,accept='application/json'):
        if 'openid-credential-issuer' in url: return signed.encode(),'application/jwt'
        return json.dumps(auth).encode(),'application/json'
    monkeypatch.setattr(val,'fetch',fetch)
    result=val.issuer_data('openid-credential-offer://?'+urlencode({'credential_offer':json.dumps(offer)}),'1.0')
    verdict=val.configuration_assessment(json.loads(result[0]),json.loads(result[1]),json.loads(result[2]),result[3])
    assert verdict['OIDC4VCI_1_0']['status']==('NON_COMPATIBLE' if tamper else 'INDETERMINE')
    assert any('signature' in c or 'JWS verified' in c for c in result[3])

@pytest.mark.parametrize('mutation',['signature','certificate','holder_private'])
def test_sd_x5c_and_private_holder_fail(signed_sd,mutation):
    key,p,d,e=signed_sd
    if mutation=='holder_private': p['cnf']={'jwk':json.loads(key.export_private())}
    else: e['x5c']=['bm90LWEtY2VydGlmaWNhdGU=']
    notes=checks(p,key,[d],e)
    assert any(n.startswith('ERROR:') for n in notes)

def test_mdoc_prompt_uses_2021_layout(mdoc):
    vc_agent.analyze_mdoc(mdoc_token(mdoc[2]()),'18013-5','test','pro','openai')
    messages=vc_agent.get_llm_client.return_value.invoke.call_args.args[0]
    assert 'ISO/IEC 18013-5:2021' in messages[1]['content']
    assert 'deviceKeyInfo.deviceKey' in messages[1]['content']
    assert 'shall be included as an unprotected header element' not in messages[1]['content']

@pytest.mark.parametrize('draft',['12','13'])
def test_correct_sdjwt_spec_reference(draft):
    for agent in (vc_agent,qr_agent):
        assert agent.spec_url_sdjwtvc(draft).endswith(f'-{draft}.html')

@pytest.mark.parametrize('transport',['direct-base64','direct-base64url','wrapped-base64','wrapped-base64url'])
def test_wallet_mdoc_transport(client,mdoc,transport):
    raw=cbor2.dumps(mdoc[2]())
    credential=base64.b64encode(raw).decode() if transport=='direct-base64' else encode(raw)
    if transport.startswith('wrapped'):
        credential=base64.b64encode(credential.encode()).decode() if transport=='wrapped-base64' else encode(credential.encode())
    response=client.post('/ai/wallet/vc',data={'vc':credential},headers={'Api-Key':'test'})
    assert response.status_code==200, response.get_data(as_text=True)
    report=base64.b64decode(response.data).decode('ascii')
    assert 'COSE signature verified successfully' in report


def test_mdoc_decoder_compatible_with_older_cbor2(monkeypatch,mdoc):
    original=val.cbor2.CBORDecoder
    calls=[]
    def older_decoder(stream,**kwargs):
        calls.append(kwargs)
        if kwargs:
            raise TypeError("'read_size' is an invalid keyword argument")
        return original(stream)
    monkeypatch.setattr(val.cbor2,'CBORDecoder',older_decoder)
    assert val.detect_format(mdoc_token(mdoc[2]()))=='mdoc'
    assert calls==[{'read_size':1},{}]


@pytest.mark.parametrize('raw',[b'\xff\xfe',cbor2.dumps({'not_a_credential':True})])
def test_binary_non_mdoc_not_accepted(client,raw):
    response=client.post('/ai/wallet/vc',data={'vc':base64.b64encode(raw).decode()},headers={'Api-Key':'test'})
    assert response.status_code==400


@pytest.mark.parametrize('route,field',[('vc','vc'),('qrcode','qrcode')])
def test_legacy_wallet_report_characters(client,monkeypatch,route,field):
    text='Observed — issuer: §§3.2–3.4; clés vérifiées; ≤ 42; → accepted ✓. Test 字.'
    if route=='vc':
        async def analyze(*a): return text
        monkeypatch.setattr(vc_agent,'process_vc_format',analyze)
    else:
        monkeypatch.setattr(qr_agent,'analyze_qrcode',lambda *a:text)
    response=client.post('/ai/wallet/'+route,data={field:base64.b64encode(b'test').decode()},headers={'Api-Key':'test'})
    assert response.status_code==200
    raw=base64.b64decode(response.data)
    # Both the existing Latin-1 client and a correct UTF-8 client read identical text.
    assert raw.decode('latin-1')==raw.decode('utf-8')==raw.decode('ascii')
    report=raw.decode('ascii')
    assert 'Observed - issuer: sections 3.2-3.4' in report
    assert 'cles verifiees' in report
    assert '<= 42; -> accepted PASS' in report
    assert r'\u5b57' in report
    assert '&#' not in report


def test_altme_mdoc_json_envelope(client,mdoc):
    # Mirrors getMdocCredentialData + AiCredentialAnalysisButton in TalaoDAO/AltMe.
    data={'id':'urn:uuid:test','type':['mDL'],'docType':'org.iso.18013.5.1.mDL',
          'issuerSigned':mdoc_token(mdoc[2]()),
          'credentialSubject':{'org.iso.18013.5.1':{'given_name':'DISPLAY VALUE, NOT SIGNED INPUT'}}}
    encoded=base64.b64encode(json.dumps(data).encode('utf-8')).decode()
    response=client.post('/ai/wallet/vc',data={'vc':encoded},headers={'Api-Key':'test'})
    assert response.status_code==200, response.get_data(as_text=True)
    report=base64.b64decode(response.data).decode('ascii')
    assert 'COSE signature verified successfully' in report
    prompt=vc_agent.get_llm_client.return_value.invoke.call_args.args[0][1]['content']
    assert 'DISPLAY VALUE, NOT SIGNED INPUT' not in prompt
    assert 'Alice' in prompt


def test_altme_mdoc_envelope_doctype_mismatch_is_reported(client,mdoc):
    data={'issuerSigned':mdoc_token(mdoc[2]()),'docType':'wrong.type'}
    response=client.post('/ai/wallet/vc',data={'vc':base64.b64encode(json.dumps(data).encode()).decode()},headers={'Api-Key':'test'})
    assert response.status_code==200
    assert 'docType does not match MSO' in base64.b64decode(response.data).decode()


@pytest.mark.parametrize('signed',['not-base64','a.b.c',encode(cbor2.dumps({'not_mdoc':True}))])
def test_altme_mdoc_envelope_invalid_signed_data_rejected(client,signed):
    data={'issuerSigned':signed,'docType':'org.iso.18013.5.1.mDL'}
    response=client.post('/ai/wallet/vc',data={'vc':base64.b64encode(json.dumps(data).encode()).decode()},headers={'Api-Key':'test'})
    assert response.status_code==400


def test_oidc4vci_draft18_displayed_as_1_0(monkeypatch,metadata):
    offer,meta,auth=metadata
    mock_discovery(monkeypatch,*metadata)
    uri='openid-credential-offer://?'+urlencode({'credential_offer':json.dumps(offer)})
    report=qr_agent.analyze_issuer_qrcode(uri,'18','','test','pro','openai')
    assert 'This report is based on OIDC4VCI 1.0.' in report
    assert 'based on OIDC4VCI 18' not in report
    messages=qr_agent.get_llm_client.return_value.invoke.call_args.args[0]
    assert 'specializing in OIDC4VCI 1.0' in messages[0]['content']
    assert 'Context (OIDC4VCI 1.0)' in messages[1]['content']
    assert 'OIDC4VCI Draft 18' not in messages[1]['content']
    assert 'Source: dataset/oidc4vci/18.md' in messages[1]['content']
    assert 'based on OIDC4VCI 13.' in qr_agent.attribution('pro','OIDC4VCI','13','openai')


def test_report_verdicts_are_human_readable(metadata):
    offer,meta,auth=metadata
    auth['dpop_signing_alg_values_supported']=[]
    result=val.configuration_assessment(offer,meta,auth)
    assert result['HAIP_1_0']['status']=='NON_COMPATIBLE'
    rendered=val.assessment_markdown(result)
    assert 'HAIP 1.0 : Incompatible' in rendered
    assert 'OIDC4VCI 1.0 : Compatible based on metadata' in rendered
    for code in ('NON_COMPATIBLE','COMPATIBLE_METADATA','AUCUNE_INCOMPATIBILITE_DETECTEE'):
        assert code not in rendered
    result=val.configuration_assessment(offer,meta,auth,comments=['NOT_VERIFIED: signer trust'])
    assert 'OIDC4VCI 1.0 : Undetermined' in val.assessment_markdown(result)


def test_report_language_is_english(monkeypatch,metadata,mdoc):
    offer,meta,auth=metadata
    mock_discovery(monkeypatch,*metadata)
    uri='openid-credential-offer://?'+urlencode({'credential_offer':json.dumps(offer)})
    report=qr_agent.analyze_issuer_qrcode(uri,'18','','test','pro','openai')
    assert 'Configuration Compatibility Assessment' in report
    assert 'Static configuration only' in report
    assert 'Compatible based on metadata' in report
    messages=qr_agent.get_llm_client.return_value.invoke.call_args.args[0]
    assert val.REPORT_LANGUAGE_INSTRUCTION in messages[0]['content']
    vc_agent.analyze_mdoc(mdoc_token(mdoc[2]()),'18013-5','test','pro','openai')
    messages=vc_agent.get_llm_client.return_value.invoke.call_args.args[0]
    assert val.REPORT_LANGUAGE_INSTRUCTION in messages[0]['content']
    for agent in (vc_agent,qr_agent):
        assert val.REPORT_LANGUAGE_INSTRUCTION in agent.style_instructions(agent.style_for('pro'),'general','1.0')
