from flask import  request, render_template, redirect, session, jsonify
import json
import logging
import random
import requests
import verifier_db_api 
from urllib.parse import urlencode
import uuid
from op_constante import credential_list, protocol_list, model_one, model_any, model_DIDAuth

logging.basicConfig(level=logging.INFO)



did_selected = 'did:tz:tz2NQkPq3FFA3zGAyG8kLcWatGbeXpHMu7yk'

def init_app(app,red, mode) :
    app.add_url_rule('/sandbox/op/console/login',  view_func=console_login, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/op/console/callback',  view_func=console_callback, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/op/console/logout',  view_func=console_logout, methods = ['GET', 'POST'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/op/console',  view_func=console, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/op/console/select',  view_func=select, methods = ['GET', 'POST'])
    app.add_url_rule('/sandbox/op/console/advanced',  view_func=advanced, methods = ['GET', 'POST'])
    app.add_url_rule('/sandbox/op/console/preview',  view_func=preview, methods = ['GET', 'POST'], defaults={'mode' : mode, "red" : red})
    app.add_url_rule('/sandbox/preview_presentation/<stream_id>',  view_func=preview_presentation_endpoint, methods = ['GET', 'POST'],  defaults={'red' : red})

    return


# parameters provided by platform
client_id = 'gajjfwdbhy'
client_secret = 'a86c8a1e-fb80-11ec-ad02-db56768956ef'


# website homepage
def console_login(mode) :
    if not session.get('is_connected') :
        data = {
                'response_type': 'code',
                'client_id': client_id,
                'state': str(random.randint(0, 99999)),
                'nonce' :  str(random.randint(10000, 999999)), 
                'redirect_uri': mode.server + 'sandbox/op/console/callback',
                'scope': 'openid'    }
        session['data'] = data
        return redirect('/sandbox/op/authorize?' + urlencode(data))
    else  :
        return redirect('/sandbox/op/console')
    


def console_callback(mode):
    if 'error' in request.args :
            session['is_connected'] = False
            return redirect('/')
    
    data = {
        'grant_type': 'authorization_code',
        'redirect_uri': mode.server + 'sandbox/op/console/callback',
        'code': request.args['code']
    }
    response = requests.post(mode.server + 'sandbox/op/token', data=data, auth=(client_id, client_secret))

    if response.status_code == 200:
        session['is_connected'] = True
    else :
        session['is_connected'] = False
    return redirect('/sandbox/op/console')
      


def console_logout(mode):
    if not session.get('is_connected') :
        return redirect('sandbox/op/console/login')
    session.clear()
    response = requests.post(mode.server + 'sandbox/logout', data="")
    return redirect('/sandbox/op/console')


def select() :
    if not session.get('is_connected') :
        return redirect('/sandbox/op/console/login')

    if request.method == 'GET' :  
        my_list = verifier_db_api.list_verifier()
        verifier_list=str()
        for data in my_list :
            data_dict = json.loads(data)
            verifier = """<tr>
                <td>""" + data_dict['company_name'] + """</td>
                <td><a href=/sandbox/op/console?client_id=""" + data_dict['client_id'] + """>""" + data_dict['client_id'] + """</a></td>
                <td>""" + data_dict['client_secret'] + """</td>
                <td>""" + data_dict['vc'] + """</td>
                </tr>"""
            verifier_list += verifier     
        return render_template('select.html', verifier_list=verifier_list) 
    else :
        if request.form['button'] == "new" :
            return redirect('/sandbox/op/console?client_id=' + verifier_db_api.create_verifier())
        elif request.form['button'] == "logout" :
            session.clear()
            return redirect ('/sandbox/op/console')
        #client_id = request.form['client_id']
        #return redirect ('/sandbox/op/console?client_id=' + client_id)


def preview (red, mode) :
    stream_id = str(uuid.uuid1())
    client_id = session['client_data']['client_id']
    verifier_data = json.loads(verifier_db_api.read_verifier(client_id))
    qrcode_message = verifier_data.get('qrcode_message', "No message")
    mobile_message = verifier_data.get('mobile_message', "No message")
    if verifier_data['vc'] == "ANY" :
        pattern = model_any
    elif verifier_data['vc'] == "DID" :
        pattern = model_DIDAuth
    else :
        pattern = model_one
        pattern["query"][0]["credentialQuery"][0]["reason"][0]["@value"] = verifier_data['reason']
        pattern["query"][0]["credentialQuery"][0]["example"]["type"] = verifier_data['vc']
    data = { "pattern": pattern }
    red.set(stream_id,  json.dumps(data))
    url = mode.server + 'sandbox/preview_presentation/' + stream_id + '?' + urlencode({'issuer' : did_selected})
    deeplink = mode.deeplink + 'app/download?' + urlencode({'uri' : url})
    return render_template('op_verifier_qrcode.html',
							url=url,
                            deeplink=deeplink,
							stream_id=stream_id,
                            qrcode_message=qrcode_message,
                            mobile_message=mobile_message,
                            landing_page_url= verifier_data['landing_page_url'],
                            title=verifier_data['title'],
                            terms_url= verifier_data.get('terms_url'),
                            privacy_url=verifier_data.get('privacy_url'),
                            company_name=verifier_data.get('company_name')
                            )
    
def preview_presentation_endpoint(stream_id, red):
    if request.method == 'GET':
        try :
            my_pattern = json.loads(red.get(stream_id).decode())['pattern']
        except :
            logging.error('red decode failed')
            red.set(stream_id + '_access',  'server_error')
            red.publish('login', json.dumps({"stream_id" : stream_id}))
            return jsonify("server error"), 500
        print(my_pattern)
        return jsonify(my_pattern)


def console(mode) :
    global vc, reason
    if not session.get('is_connected') :
        return redirect('/sandbox/op/console/login')
    if request.method == 'GET' :
        if not request.args.get('client_id') :
            return redirect('/sandbox/op/console/select')
        else  :
            session['client_id'] = request.args.get('client_id')
        session['client_data'] = json.loads(verifier_db_api.read_verifier(session['client_id']))
        vc_select = str()
        for key, value in credential_list.items() :
                if key ==   session['client_data']['vc'] :
                    vc_select +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select +=  "<option value=" + key + ">" + value + "</option>"

        return render_template('console.html',
                title = session['client_data'].get('title'),
                contact_name = session['client_data'].get('contact_name'),
                contact_email = session['client_data'].get('contact_email'),
                privacy_url = session['client_data'].get('privacy_url'),
                landing_page_url = session['client_data'].get('landing_page_url'),
                terms_url = session['client_data'].get('terms_url'),
                issuer = mode.server + "sandblox/op",
                client_id= session['client_data']['client_id'],
                client_secret= session['client_data']['client_secret'],
                token=mode.server + 'sandbox/op/authorize',
                authorization=mode.server + 'sandbox/op/token',
                logout=mode.server + 'sandbox/op/logout',
                userinfo=mode.server + 'sandbox/op/userinfo',
                company_name = session['client_data']['company_name'],
                reason = session['client_data']['reason'],
                qrcode_message = session['client_data'].get('qrcode_message', ""),
                mobile_message = session['client_data'].get('mobile_message', ""),
                vc_select=vc_select,
                )
    if request.method == 'POST' :
        if request.form['button'] == "new" :
            return redirect('/sandbox/op/console?client_id=' + verifier_db_api.create_verifier())
        
        elif request.form['button'] == "select" :
            return redirect ('/sandbox/op/console/select')
        
        elif request.form['button'] == "delete" :
            verifier_db_api.delete_verifier( request.form['client_id'])
            return redirect ('/sandbox/op/console')

        elif request.form['button'] == "logout" :
            session.clear()
            return redirect ('/sandbox/op/console')

        elif request.form['button'] == "advanced" :
            return redirect ('/sandbox/op/console/advanced')
        
        elif request.form['button'] in [ "update", "preview"] :
            session['client_data']['contact_name'] = request.form['contact_name']
            session['client_data']['title'] = request.form['title']
            session['client_data']['contact_email'] = request.form['contact_email']
            session['client_data']['privacy_url'] = request.form['privacy_url']
            session['client_data']['landing_page_url'] = request.form['landing_page_url']
            session['client_data']['terms_url'] = request.form['terms_url']
            session['client_data']['client_id'] =  request.form['client_id']
            session['client_data']['client_secret'] = request.form['client_secret']
            session['client_data']['company_name'] = request.form['company_name']
            session['client_data']['reason'] = request.form.get('reason', "")
            session['client_data']['vc'] = request.form['vc']
            session['client_data']['qrcode_message'] = request.form['qrcode_message']
            session['client_data']['mobile_message'] = request.form['mobile_message']          
            verifier_db_api.update_verifier(request.form['client_id'], json.dumps(session['client_data']))
            if request.form['button'] == "preview" :
                return redirect ('/sandbox/op/console/preview')
            return redirect('/sandbox/op/console?client_id=' + request.form['client_id'])
        else :
            return redirect('/sandbox/op/console')


def advanced() :
    global vc, reason
    if not session.get('is_connected') :
        return redirect('/sandbox/op/console/login')
    if request.method == 'GET' :
        session['client_data'] = json.loads(verifier_db_api.read_verifier(session['client_id']))
        protocol_select = vc_select = str()       
        for key, value in credential_list.items() :
                if key ==   session['client_data']['vc'] :
                    vc_select +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select +=  "<option value=" + key + ">" + value + "</option>"

        for key, value in protocol_list.items() :
                if key ==   session['client_data'].get('protocol', "") :
                    protocol_select +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    protocol_select +=  "<option value=" + key + ">" + value + "</option>"
        if session['client_data'].get('emails') :
            emails_filtering = """<input class="form-check-input" checked type="checkbox" name="emails" value="ON" id="flexCheckDefault">"""
        else :
            emails_filtering = """<input class="form-check-input" type="checkbox" name="emails" value="ON" id="flexCheckDefault">"""
        return render_template('advanced.html',
                client_id = session['client_data']['client_id'],
                authorized_emails = session['client_data']['authorized_emails'],
                protocol = session['client_data']['protocol'],
                emails_filtering=emails_filtering,
                protocol_select=protocol_select
                )
    if request.method == 'POST' :

        if request.form['button'] == "back" :
            return redirect ('/sandbox/op/console?client_id=' + request.form['client_id'] )
        
        elif request.form['button'] == "update" :
            session['client_data']['authorized_emails'] = request.form.get('authorized_emails', "")
            session['client_data']['protocol'] = request.form['protocol']
            session['client_data']['emails'] = request.form.get('emails')
            verifier_db_api.update_verifier( request.form['client_id'], json.dumps(session['client_data']))
            return redirect('/sandbox/op/console?client_id=' + request.form['client_id'])
          

