
from flask import request, render_template
from flask import Response, jsonify
import json
import uuid
from urllib.parse import urlencode
import logging
from datetime import datetime
import didkit # VC signature sdk
from components import message, sms
logging.basicConfig(level=logging.INFO)

CODE_LIFE = 5 * 60 # sec

TRUSTED_ISSUERS = [
    'did:web:site.ageproofpoc.dns.id360docaposte.com:certificates'
]
WEBLINK = "https://app.jeprouvemonage.fr/jpma"


def init_app(app, red, mode):
    # endpoints for OpenId customer application
    app.add_url_rule('/face2face/wallet/presentation/<stream_id>',  view_func=face2face_presentation, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/face2face/wallet/followup',  view_func=face2face_followup, methods=['GET'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/face2face/wallet/stream', view_func=face2face_stream, methods=['GET'], defaults={'red': red, 'mode': mode})
    app.add_url_rule('/face2face', view_func=face2face, methods=['GET', 'POST'], defaults={'red': red, 'mode': mode})

    return



def face2face(red, mode):
    stream_id = str(uuid.uuid1())
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
            'reason': 'face2face experimentation' 
        }
    )
    pattern['challenge'] = stream_id
    pattern['domain'] = mode.server
    data = {'pattern': pattern}
    red.setex(stream_id, CODE_LIFE, json.dumps(data))
    url = f'{mode.server}face2face/wallet/presentation/{stream_id}'
    return render_template("./verifier_oidc/verifier_qrcode_only_jpma.html", url=url, stream_id=stream_id)


async def face2face_presentation(stream_id, red, mode):
    def manage_error(msg, code=403):
        value = json.dumps({
            'access': 'access_denied',
            'user': credential['credentialSubject']['id']
        })
        red.setex(stream_id + '_data', CODE_LIFE, value)
        event_data = json.dumps({'stream_id': stream_id})           
        red.publish('face2face', event_data)
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
            red.publish('face2face', event_data)
            logging.warning('link expired, return 408 to wallet and display error page to desktop')
            return jsonify('REQUEST_TIMEOUT'), 408
        return jsonify(my_pattern)

    if request.method == 'POST':  
        presentation = request.form['presentation']
        result_presentation = await didkit.verify_presentation(presentation, '{}')
        logging.info('check presentation with didkit.verify = %s', result_presentation )
        credential = json.loads(presentation).get('verifiableCredential')
        
        if not credential:
            value = json.dumps({
                'access': 'access_denied',
                'user': 'refuse'
            })
            red.setex(stream_id + '_data', CODE_LIFE, value)
            event_data = json.dumps({'stream_id': stream_id})           
            red.publish('face2face', event_data)
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
        red.publish('face2face', event_data)        
        return jsonify('ok')


def face2face_followup(red, mode):
    stream_id = request.args.get('stream_id')
    stream_id_data = json.loads(red.get(stream_id + '_data').decode())
    if stream_id_data['access'] != 'ok':
        return jsonify("User refuses to present VC, add new page here")
    return render_template('face2face.html')


def face2face_stream(red, mode):
    def login_event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('face2face')
        for pub_message in pubsub.listen():
            if pub_message['type'] == 'message':
                yield 'data: %s\n\n' % pub_message['data'].decode()
    headers = {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    }
    return Response(login_event_stream(red), headers=headers)

