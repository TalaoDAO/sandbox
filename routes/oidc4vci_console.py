from flask import  request, render_template, redirect, session
import json
import logging
import copy
import db_api 
from oidc4vc_constante import  landing_page_style_list, oidc4vc_profile_list, guest_landing_page_style_list
from oidc4vc_constante import vc_format, oidc4vci_draft
import profile
import oidc4vc
from profile import profile

logging.basicConfig(level=logging.INFO)


def init_app(app, red, mode):
    app.add_url_rule('/issuer/console/logout', view_func=oidc4vc_nav_logout, methods=['GET', 'POST'])
    app.add_url_rule('/issuer/console', view_func=oidc4vc_issuer_console, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/issuer/console/select', view_func=oidc4vc_issuer_select, methods=['GET', 'POST'])
    app.add_url_rule('/issuer/console/advanced', view_func=oidc4vc_issuer_advanced, methods=['GET', 'POST'])
    #app.add_url_rule('/issuer/preview_presentation/<stream_id>', view_func=oidc4vc_issuer_preview_presentation_endpoint, methods=['GET', 'POST'],  defaults={'red': red})
    # nav bar option
    app.add_url_rule('/issuer/nav/logout',  view_func=oidc4vc_nav_logout, methods=['GET'])
    app.add_url_rule('/issuer/nav/create',  view_func=oidc4vc_nav_create, methods=['GET'], defaults= {'mode': mode})
    return


def oidc4vc_nav_logout():
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    session.clear()
    return redirect('/sandbox/saas4ssi')


def oidc4vc_issuer_select():
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    my_list = db_api.list_oidc4vc_issuer()
    issuer_list = str()
    for issuer_data in my_list:
        data_dict = json.loads(issuer_data)         
        client_id = data_dict['client_id']
        if data_dict['user'] == "all" or session['login_name'] in [data_dict['user'], "admin"]:
            curve = json.loads(data_dict['jwk']).get('crv')
            if not curve:
                curve = 'RSA'
            vm = data_dict['verification_method']
            issuer = """<tr>
                <td>""" + data_dict.get('application_name', "unknown") + """</td>
                <td>""" +  data_dict['profile'] + """</td>
                <td><a href=/issuer/console?client_id=""" + client_id + """>""" + client_id + """</a></td>
                <td>""" + data_dict['did'] + """</td> 
                <td>""" + vm + """</td> 
                <td>""" + curve + """</td>
                </tr>"""
            issuer_list += issuer
    return render_template('issuer_oidc/issuer_select.html', issuer_list=issuer_list, login_name=session['login_name']) 

    
def oidc4vc_nav_create(mode):
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    return redirect('/issuer/console?client_id=' + db_api.create_oidc4vc_issuer(mode,  user=session['login_name']))



def oidc4vc_issuer_console(mode):
    global reason
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    if request.method == 'GET':
        if not request.args.get('client_id'):
            return redirect('/issuer/console/select')
        else:
            session['client_id'] = request.args.get('client_id')
        session['client_data'] = json.loads(db_api.read_oidc4vc_issuer(session['client_id']))

        issuer_landing_page_select = str()
        if session['login_name'] == 'admin':
            page_style_list = landing_page_style_list
        else:
            page_style_list = guest_landing_page_style_list
        for key, value in page_style_list.items():
            if key == session['client_data'].get('issuer_landing_page'):
                issuer_landing_page_select +=  "<option selected value=" + key + ">" + value + "</option>"
            else:
                issuer_landing_page_select += "<option value=" + key + ">" + value + "</option>"
        
        issuer_api_endpoint = mode.server + 'sandbox/oidc4vc/issuer/api'
        
        return render_template(
            'issuer_oidc/issuer_console.html',
            login_name=session['login_name'],
            credential_offer_uri="" if not session['client_data'].get('credential_offer_uri')  else "checked" ,
            deferred_flow="" if not session['client_data'].get('deferred_flow')  else "checked" ,
            issuer_id_as_url="" if not session['client_data'].get('issuer_id_as_url')  else "checked" ,
            application_name=session['client_data'].get('application_name', 'Unknown'),
            client_secret=session['client_data']['client_secret'],
            issuer_api_endpoint=issuer_api_endpoint,
            client_id=session['client_data']['client_id'],
            page_title=session['client_data']['page_title'],
            page_subtitle=session['client_data']['page_subtitle'],
            issuer_landing_page_select=issuer_landing_page_select,
        )
    if request.method == 'POST':
        if request.form['button'] == "delete":
            db_api.delete_oidc4vc_issuer( request.form['client_id'])
            return redirect('/issuer/console')
        else:
            session['client_data']['credential_offer_uri'] = request.form.get('credential_offer_uri') 
            session['client_data']['deferred_flow'] = request.form.get('deferred_flow') 
            session['client_data']['issuer_id_as_url'] = request.form.get('issuer_id_as_url') 
            session['client_data']['page_title'] = request.form['page_title']
            session['client_data']['page_subtitle'] = request.form['page_subtitle']
            session['client_data']['issuer_landing_page'] = request.form['issuer_landing_page']
            session['client_data']['client_id'] =  request.form['client_id']
            session['client_data']['application_name'] = request.form['application_name']
            
            if request.form['button'] == "preview":
                return redirect('/issuer/console/preview')
            
            if request.form['button'] == "advanced":
                return redirect('/issuer/console/advanced')
            
            if request.form['button'] == "update":
                
                db_api.update_oidc4vc_issuer(request.form['client_id'], json.dumps(session['client_data']))
                return redirect('/issuer/console?client_id=' + request.form['client_id'])

            if request.form['button'] == "copy":
                new_client_id = db_api.create_oidc4vc_issuer(mode,  user=session['login_name'])
                new_data = copy.deepcopy(session['client_data'])
                new_data['application_name'] = new_data['application_name'] + ' (copie)'
                new_data['client_id'] = new_client_id
                new_data['user'] = session['login_name']
                db_api.update_oidc4vc_issuer(new_client_id, json.dumps(new_data))
                return redirect('/issuer/console?client_id=' + new_client_id)


async def oidc4vc_issuer_advanced():
    global reason
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    
    if request.method == 'GET':
        session['client_data'] = json.loads(db_api.read_oidc4vc_issuer(session['client_id']))
        oidc4vc_profile_select = str()
        for key, value in oidc4vc_profile_list.items():
            if key ==  session['client_data'].get('profile', "DEFAULT"):
                oidc4vc_profile_select +=  "<option selected value=" + key + ">" + value + "</option>"
            else:
                oidc4vc_profile_select += "<option value=" + key + ">" + value + "</option>"          

        did = session['client_data'].get('did', "")
        did_document = oidc4vc.did_resolve_lp(did)
        jwk = json.dumps(json.loads(session['client_data']['jwk']), indent=4)
    
        return render_template(
            'issuer_oidc/issuer_advanced.html',
            client_id=session['client_data']['client_id'],
            jwk=jwk,
            credential_manifest_support="" if not session['client_data'].get('credential_manifest_support')  else "checked" ,
            verification_method=session['client_data'].get('verification_method', ""),
            oidc4vc_profile_select=oidc4vc_profile_select,
            did=session['client_data'].get('did', ""),
            did_document=json.dumps(did_document, indent=4),
        )
        
    if request.method == 'POST':     
        session['client_data'] = json.loads(db_api.read_oidc4vc_issuer(session['client_id']))
        if request.form['button'] == "back":
            return redirect('/issuer/console?client_id=' + request.form['client_id'])

        if request.form['button'] == "update":
            session['client_data']['profile'] = request.form['profile']
            session['client_data']['did'] = request.form['did']
            session['client_data']['verification_method'] = request.form['verification_method']
            session['client_data']['jwk'] = request.form['jwk']           
            db_api.update_oidc4vc_issuer(request.form['client_id'], json.dumps(session['client_data']))
            return redirect('/issuer/console/advanced')