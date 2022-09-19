"""
def get_version() -> str: ...
def generate_ed25519_key() -> str: ...
def key_to_did(method_pattern: str, jwk: str) -> str: ...
async def key_to_verification_method(method_pattern: str, jwk: str) -> str: ...
async def issue_credential(credential: str, proof_options: str, key: str) -> str: ...
async def verify_credential(credential: str, proof_options: str) -> str: ...
async def issue_presentation(presentation: str, proof_options: str, key: str) -> str: ...
async def verify_presentation(presentation: str, proof_options: str) -> str: ...
async def resolve_did(did: str, input_metadata: str) -> str: ...
async def dereference_did_url(did_url: str, input_metadata: str) -> str: ...
async def did_auth(did: str, options: str, key: str) -> str: ...
"""

from flask import jsonify, request, render_template, Response, redirect, session
import json
from datetime import timedelta, datetime
import uuid
import didkit
import logging
from urllib.parse import urlencode
import requests
import db_api
import ebsi
import base64

logging.basicConfig(level=logging.INFO)
OFFER_DELAY = timedelta(seconds= 10*60)


def init_app(app,red, mode) :
    app.add_url_rule('/sandbox/op/issuer/<issuer_id>',  view_func=issuer_landing_page, methods = ['GET', 'POST'], defaults={'red' :red, 'mode' : mode})
    app.add_url_rule('/sandbox/op/issuer_endpoint/<issuer_id>/<stream_id>',  view_func=issuer_endpoint, methods = ['GET', 'POST'], defaults={'red' :red})
    app.add_url_rule('/sandbox/op/issuer_stream',  view_func=issuer_stream, methods = ['GET', 'POST'], defaults={'red' :red})
    app.add_url_rule('/sandbox/op/issuer_followup',  view_func=issuer_followup, methods = ['GET'])
    app.add_url_rule('/sandbox/op/login_password/<issuer_id>',  view_func=login_password, methods = ['GET', 'POST'])

    return


def login_password(issuer_id) :
    if request.method == 'GET' :
        try :
            issuer_data = json.loads(db_api.read_issuer(issuer_id))
        except :
            logging.error('issuer id not found')
            return render_template('op_issuer_removed.html')
        return render_template ('login_password.html',
            issuer_id=issuer_id,
            page_title=issuer_data['page_title'],
            page_subtitle=issuer_data['page_subtitle'],
            page_description=issuer_data['page_description'],
            title=issuer_data['title'],
            qrcode_message=issuer_data['qrcode_message'],
            landing_page_url=issuer_data['landing_page_url'],
            privacy_url=issuer_data['privacy_url'],
            terms_url=issuer_data['terms_url'],
            mobile_message=issuer_data['mobile_message'],
            page_background_color = issuer_data['page_background_color'],
            page_text_color = issuer_data['page_text_color'],
            qrcode_background_color = issuer_data['qrcode_background_color'])
    if request.method == 'POST' :
        session['username'] = request.form['username']
        session['password'] = request.form['password']
        session['login_password'] = True
        print("post call")
        return redirect('/sandbox/op/issuer/' + session['issuer_id'])


"""
Direct access to one VC with filename passed as an argument
"""
def issuer_landing_page(issuer_id, red, mode) :
    session['is_connected'] = True
    try :
        issuer_data = json.loads(db_api.read_issuer(issuer_id))
    except :
        logging.error('issuer id not found')
        return render_template('op_issuer_removed.html')

    if issuer_data['credential_requested'] == "login" and not session.get('login_password') :
        session['issuer_id'] = issuer_id
        return redirect('/sandbox/op/login_password/' + issuer_id)
    
    try :
        credential = json.load(open('./verifiable_credentials/' + issuer_data['credential_to_issue'] + '.jsonld'))
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential["issuer"] ="did:ebsi:"
    except :
        logging.error('credential not found %s', issuer_data['credential_to_issue'])
        return render_template('op_issuer_removed.html')
    try :
        credential_manifest = json.load(open('./credential_manifest/' + issuer_data['credential_to_issue'] + '_credential_manifest.json'))
    except :
        logging.error('credential manifest not found or error %s', issuer_data['credential_to_issue'])
        return render_template('op_issuer_removed.html')
    
    if issuer_data['method'] == "ebsi" :
        issuer_did =  issuer_data['did_ebsi']
    elif issuer_data['method'] == "relay" :
        issuer_did = 'did:tz:tz2NQkPq3FFA3zGAyG8kLcWatGbeXpHMu7yk'
    else : 
        issuer_did = didkit.key_to_did(issuer_data['method'], issuer_data['jwk'])
    
    # update credential manifest
    credential_manifest['id'] = str(uuid.uuid1())
    credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
    credential_manifest['output_descriptors'][0]['schema'] = "https://github.com/TalaoDAO/wallet-tools/blob/main/test/CredentialOffer2/" + issuer_data['credential_to_issue'] + '.jsonld'
    credential_manifest['output_descriptors'][0]['display']['title']['fallback'] = issuer_data['card_title']
    credential_manifest['output_descriptors'][0]['display']['subtitle']['fallback'] = issuer_data['card_subtitle']
    credential_manifest['output_descriptors'][0]['display']['description']['fallback'] = issuer_data['card_description']
    credential_manifest['output_descriptors'][0]['styles'] = {
            'background' : {'color' : issuer_data['card_background_color']},
            'text' : { 'color' : issuer_data['card_text_color']}}
    
    credential_manifest['issuer']['id'] = issuer_did
    credential_manifest['issuer']['name'] = issuer_data['company_name']
    credential_manifest['presentation_definition'] = dict()
    if issuer_data['credential_requested'] in ["DID", "login"] and issuer_data['credential_requested_2'] == "DID" : # No credential requested to issue 
        pass
    else :
        credential_manifest['presentation_definition'] = {"id": str(uuid.uuid1()), "input_descriptors": list()}
        
        if issuer_data['credential_requested'] != "DID" :
            input_descriptor = {"id": str(uuid.uuid1()),
                        "purpose" : issuer_data['reason'],
                        "constraints": {
                            "fields": [
                                {"path": ["$.type"],
                                "filter": {"type": "string",
                                            "pattern": issuer_data['credential_requested']}
                                }]}}
            credential_manifest['presentation_definition']['input_descriptors'].append(input_descriptor)
     
        if issuer_data['credential_requested_2'] != "DID" :  
            input_descriptor_2 = {"id": str(uuid.uuid1()),
                        "purpose" : issuer_data.get('reason_2',""),
                        "constraints": {
                            "fields": [
                                {"path": ["$.type"],
                                "filter": {"type": "string",
                                            "pattern": issuer_data['credential_requested_2']}
                                }]}}
            credential_manifest['presentation_definition']['input_descriptors'].append(input_descriptor_2)

    #logging.info("credential manifest = %s", credential_manifest)
    if not request.args.get('id') :
        logging.warning("no id passed by application")

    credentialOffer = {
        "id" : request.args.get('id'),
        "type": "CredentialOffer",
        "challenge" : str(uuid.uuid1()),
        "domain" : "https://altme.io",
        "credentialPreview": credential,
        "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z",
        "credential_manifest" : credential_manifest,
    }   
    stream_id = str(uuid.uuid1())
    url = mode.server + "sandbox/op/issuer_endpoint/" + issuer_id + '/' + stream_id + '?issuer=' + issuer_did 
    deeplink_altme = mode.altme_deeplink + 'app/download?' + urlencode({'uri' : url })
    red.setex(stream_id, 180, json.dumps(credentialOffer))
    if issuer_data['credential_requested'] == "login" :
        red.setex(stream_id + "_login", 180, json.dumps({"username" : session['username'],
                                                         "password" : session["password"]
                                                          } ))

    if not issuer_data.get('landing_page_style') :
        qrcode_page = "op_issuer_qrcode_2.html"
    else : 
        qrcode_page = issuer_data.get('landing_page_style')
  
    return render_template(qrcode_page,
                                url=url,
                                deeplink_altme=deeplink_altme,
                                stream_id=stream_id,
                                issuer_id=issuer_id,
                                page_title=issuer_data['page_title'],
                                page_subtitle=issuer_data['page_subtitle'],
                                page_description=issuer_data['page_description'],
                                title=issuer_data['title'],
                                qrcode_message=issuer_data['qrcode_message'],
                                landing_page_url=issuer_data['landing_page_url'],
                                privacy_url=issuer_data['privacy_url'],
                                terms_url=issuer_data['terms_url'],
                                mobile_message=issuer_data['mobile_message'],
                                page_background_color = issuer_data['page_background_color'],
                                page_text_color = issuer_data['page_text_color'],
                                qrcode_background_color = issuer_data['qrcode_background_color'],
                                )


async def issuer_endpoint(issuer_id, stream_id, red):
    try : 
        credentialOffer = red.get(stream_id).decode()
        issuer_data = json.loads(db_api.read_issuer(issuer_id))
    except :
        logging.error("red.get(id) errorn offer expired")
        data = json.dumps({'stream_id' : stream_id,
                            "result" : False,
                            "message" : "Offer expired"})
        red.publish('op_issuer', data)
        return jsonify("Unauthorized"),400 
    
    # wallet GET
    if request.method == 'GET':
        return jsonify(credentialOffer)
                        
    # wallet POST
    if request.method == 'POST':
        if not issuer_data :
            logging.error("Unhauthorized")
            data = json.dumps({'stream_id' : stream_id,
                            "result" : False,
                            "message" : "Offer expired"})
            red.publish('op_issuer', data)
            return jsonify("Unauthorized"),400  
     
        # send data to webhook
        headers = {
                    "key" : issuer_data['client_secret'],
                    "Content-Type": "application/json" 
                    }       
        url = issuer_data['webhook']
        payload = { 'event' : 'ISSUANCE',
                    'holder' : json.loads(request.form['presentation'])['holder'],
                    'vp': json.loads(request.form['presentation']),
                    "id": request.form.get('id')
                    }
        if issuer_data['credential_requested'] == 'login' :
            user_pass = json.loads(red.get(stream_id + "_login").decode())
            usrPass = (user_pass['username'] + ':' + user_pass['password']).encode()
            b64Val = base64.b64encode(usrPass) 
            headers["Authorization"] = "Basic " + b64Val.decode()
        
        r = requests.post(url,  data=json.dumps(payload), headers=headers)
        if not 199<r.status_code<300 :
            logging.error('issuer failed to call application, status code = %s', r.status_code)
            data = json.dumps({'stream_id' : stream_id,
                            "result" : False,
                            "message" : "Issuer failed to call application"})
            red.publish('op_issuer', data)
            return jsonify("application error"),500    
        logging.info('status code ok')
        
        try :
            data_received = r.json()
        except :
            logging.error('aplication data are not json')
            data = json.dumps({'stream_id' : stream_id,
                            "result" : False,
                            "message" : "Application data are not json"})
            red.publish('op_issuer', data)
            return jsonify("application error"),500

        # credential is signed by external issuer
        if issuer_data['method'] == "relay" :
            # send event to front to go forward callback
            data = json.dumps({'stream_id' : stream_id,"result" : True})
            red.publish('op_issuer', data)
            print('credential sent to wallet', data_received)
            return jsonify(data_received)

        # credential is signed by issuer   
        credential =  json.loads(credentialOffer)['credentialPreview']
        credential['expirationDate'] =  (datetime.now().replace(microsecond=0) + timedelta(days= 365)).isoformat() + "Z"
        credential['id'] = "urn:uuid:" + str(uuid.uuid4())
        credential['credentialSubject']['id'] = request.form['subject_id']
        credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"

        # extract data sent by application and merge them with verifiable credential data
        credential["credentialSubject"] = data_received
       
        # sign credential
        if issuer_data['method'] == "ebsi" :
            logging.warning("EBSI issuer")
            credential["issuer"] = issuer_data['did_ebsi']
            signed_credential = ebsi.lp_sign(credential, issuer_data['jwk'], issuer_data['did_ebsi'])
        else :
            credential["issuer"] = didkit.key_to_did(issuer_data['method'], issuer_data['jwk'])  
            didkit_options = {
                "proofPurpose": "assertionMethod",
                "verificationMethod": await didkit.key_to_verification_method(issuer_data['method'], issuer_data['jwk'])
            }
            try :
                signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_data['jwk']
                )
            except :
                message = 'Signature failed, application failed to return correct data'
                logging.error(message)
                logging.error("credential to sign = %s", credential)
                data = json.dumps({'stream_id' : stream_id,
                            "result" : False,
                            "message" : message})
                red.publish('op_issuer', data)
                return jsonify("server error, signature failed"),500
                
            logging.info('signature ok')
       
        # send credential signed to application
        headers = {
                    "key" : issuer_data['client_secret'],
                    "Content-Type": "application/json" 
                    }      
        url = issuer_data['webhook']
        payload = { 'event' : 'SIGNED_CREDENTIAL',
                    'vc': json.loads(signed_credential),
                    "id": request.form.get('id')
                    }
        r = requests.post(url,  data=json.dumps(payload), headers=headers)
        if not 199<r.status_code<300 :
            logging.error('issuer failed to send signed credential, status code = %s', r.status_code)
        else :
            logging.info('signed credential sent')
        # send event to front to go forward callback
        data = json.dumps({'stream_id' : stream_id,"result" : True})
        red.publish('op_issuer', data)
        return jsonify(signed_credential)
        

def issuer_followup():  
    if not session.get('is_connected') :
        logging.error('user is not connectd')
        return render_template('op_issuer_removed.html',next = issuer_data['issuer_landing_page'])
    session.clear()
    issuer_id = request.args.get('issuer_id')
    issuer_data = json.loads(db_api.read_issuer(issuer_id))
    if request.args.get('message') :
        return render_template('op_issuer_failed.html', next = issuer_data['issuer_landing_page'])
    try :
        issuer_data = json.loads(db_api.read_issuer(issuer_id))
    except :
        return render_template('op_issuer_removed.html',next = issuer_data['issuer_landing_page'])
    return redirect (issuer_data['callback'])
    
    
# server event push for user agent EventSource
def issuer_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('op_issuer')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()  
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)


