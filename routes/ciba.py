
from flask import request, render_template
from flask import Response, jsonify
import json
import uuid
from urllib.parse import urlencode
import logging
from datetime import datetime
import didkit # VC signature sdk
from components import message, sms

# console logger
logging.basicConfig(level=logging.INFO)


ACCESS_TOKEN_LIFE = 180 # sec access token is not used 
QRCODE_LIFE = 5 * 60  # sec
CODE_LIFE = 5 * 60 # sec

TRUSTED_ISSUERS = [
    'did:web:site.ageproofpoc.dns.id360docaposte.com:certificates'
]


CONTACT = 'healthcheck@jeprouvemonage.fr'
WEBLINK = "https://app.jeprouvemonage.fr/jpma"
EMAIL_MESSAGE = "Erreur 500 sur verifier de prod"


def init_app(app, red, mode):
    # endpoints for OpenId customer application
    app.add_url_rule('/ciba/wallet/presentation/<stream_id>',  view_func=presentation, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/ciba/wallet/followup',  view_func=followup, methods=['GET'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/ciba/wallet/stream', view_func=ciba_stream, methods=['GET'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/ciba', view_func=ciba, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    return


def ciba(red, mode):
    if request.method == 'GET':
        stream_id = str(uuid.uuid1())
        return render_template('ciba.html', stream_id=stream_id)
    else:
        email_to = request.form['email_to']
        phone_to = request.form['phone_to']
        stream_id = request.form['stream_id']
        if email_to and not phone_to:
            wallet_message(email_to, stream_id, red, mode)
        elif phone_to and not email_to:
            wallet_message(phone_to, stream_id, red, mode)
        else:
            return render_template('ciba.html', stream_id=stream_id)
        return render_template('ciba_wait.html', stream_id=stream_id)


def wallet_message(to, stream_id, red, mode):
    pattern = {
                'type': 'VerifiablePresentationRequest',
                'query': [
                    {
                        'type': 'QueryByExample',
                        'credentialQuery': []
                    }
                ]
            }
    pattern['query'][0]['credentialQuery'].append(
            {
                'example': 
                    {'type': 'AgeOver18'},
                'reason': 'Ciba experimentation' 
            }) 
    pattern['challenge'] = stream_id
    pattern['domain'] = mode.server
    data = { 
        'pattern': pattern,
    }
    red.setex(stream_id, QRCODE_LIFE, json.dumps(data))
    url = f'{mode.server}ciba/wallet/presentation/{stream_id}'
    deeplink_jpma = f'{WEBLINK}?' + urlencode({'uri': url})
    if to[:3] == "+33":
        logging.info('send SMS')
        sms.send_code(to, deeplink_jpma, mode)
    else:
        logging.info('send email')
        message.message('JPMA link', to, deeplink_jpma, mode)
    return


async def presentation(stream_id, red, mode):
    def manage_error(msg, code=403):
        value = json.dumps({
            'access': 'access_denied',
            'user': credential['credentialSubject']['id']
            })
        red.setex(stream_id + '_DIDAuth', CODE_LIFE, value)
        event_data = json.dumps({'stream_id': stream_id})           
        red.publish('ciba', event_data)
        logging.error(msg)
        return jsonify(msg), code
    
    if request.method == 'GET':
        try:
            my_pattern = json.loads(red.get(stream_id).decode())['pattern']
        except Exception:
            value = json.dumps({
                'access': 'access_denied',
                'user': 'unknown'
                })
            event_data = json.dumps({'stream_id': stream_id})           
            red.publish('ciba', event_data)
            logging.warning('QR code expired, return 408 to wallet and display error page to desktop')
            return jsonify('REQUEST_TIMEOUT'), 408
        
        return jsonify(my_pattern)

    if request.method == 'POST':  
        # Content-Type: multipart/form-data; boundary=--dio-boundary-0879526566 
        
        # get verifiable presentation
        presentation = request.form['presentation']

        result_presentation = await didkit.verify_presentation(presentation, '{}')
        logging.info('check presentation with didkit.verify = %s', result_presentation )

        # If the user refuses to present his credential, wallet sends back an empty presentation
        credential = json.loads(presentation).get('verifiableCredential')
        
        if not credential:
            value = json.dumps({
                'access': 'access_denied',
                'user': 'refuse'
            })
            red.setex(stream_id + '_data', CODE_LIFE, value)
            event_data = json.dumps({'stream_id': stream_id})           
            red.publish('ciba', event_data)
            logging.warning('User refuses, return 401 to wallet and display error page to desktop')
            return jsonify('REQUEST_TIMEOUT'), 401

        result_credential = await didkit.verify_credential(json.dumps(credential), '{}')
        if json.loads(result_credential)['errors']:       
            return manage_error('credential signature check failed')
        if credential['credentialSubject']['id'] != json.loads(presentation)['holder']:
            return manage_error('holder does not match subject.id')
        if (credential.get('expirationDate') <  datetime.now().replace(microsecond=0).isoformat() + 'Z'):
            return manage_error('credential expired')
        if credential['issuer'] not in TRUSTED_ISSUERS:
            return manage_error('Issuer not in trusted list')
        if credential['credentialSubject']['type'] not in ['AgeOver18', 'AgeOver15']:
            return manage_error('VC type does not match')
        
        # store data in redis
        value = json.dumps({
                    'access': 'ok',
                    'vp': json.loads(presentation),
                    'user': json.loads(presentation)['holder'],
                    'issuer': credential['issuer']
                    })
        red.setex(stream_id + '_data', CODE_LIFE, value)
        event_data = json.dumps({'stream_id': stream_id})           
        red.publish('ciba', event_data)        
        return jsonify('ok')


def followup(red, mode):
    """
    check if user is connected or not and redirect data to authorization server
    """
    stream_id = request.args.get('stream_id')
    stream_id_data = json.loads(red.get(stream_id + '_data').decode())
    if stream_id_data['access'] != 'ok':
        return jsonify("User refuses to present VC, add new page here")
    return render_template('ciba_access_ok.html')


def ciba_stream(red, mode):
    """
    Push data to front -> event stream
    """
    def login_event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('ciba')
        for pub_message in pubsub.listen():
            if pub_message['type'] == 'message':
                yield 'data: %s\n\n' % pub_message['data'].decode()
    headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    }
    return Response(login_event_stream(red), headers=headers)

