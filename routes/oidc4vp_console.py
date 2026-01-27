from flask import  request, render_template, redirect, session, flash
import json
import copy
import logging
import db_api 
import oidc4vc
from oidc4vc_constante import oidc4vc_verifier_credential_list, guest_oidc4vc_verifier_credential_list, predefined_presentation_uri_list
from oidc4vc_constante import oidc4vc_verifier_landing_page_style_list, oidc4vc_profile_list, guest_oidc4vc_verifier_landing_page_style_list
from oidc4vc_constante import client_id_scheme_list


logging.basicConfig(level=logging.INFO)

did_selected = 'did:tz:tz2NQkPq3FFA3zGAyG8kLcWatGbeXpHMu7yk'

def init_app(app,red, mode):
    app.add_url_rule('/sandbox/verifier/console/logout',  view_func=oidc4vc_verifier_console_logout, methods = ['GET', 'POST'])
    app.add_url_rule('/sandbox/verifier/console',  view_func=oidc4vc_verifier_console, methods = ['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/console/select',  view_func=oidc4vc_verifier_console_select, methods = ['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/console/advanced',  view_func=oidc4vc_verifier_advanced, methods = ['GET', 'POST'])

    # nav bar option
    app.add_url_rule('/sandbox/verifier/nav/logout',  view_func=oidc4vc_verifier_nav_logout, methods = ['GET'])
    app.add_url_rule('/sandbox/verifier/nav/create',  view_func=oidc4vc_verifier_nav_create, methods = ['GET'], defaults= {'mode': mode})
    return

    
def oidc4vc_verifier_nav_logout():
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    session.clear()
    return redirect('/sandbox/saas4ssi')


def oidc4vc_verifier_nav_create(mode):
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    return redirect('/sandbox/verifier/console?client_id=' + db_api.create_oidc4vc_verifier(mode, user=session['login_name']))


def oidc4vc_verifier_console_logout():
    if session.get('is_connected'):
        session.clear()
    return redirect('/sandbox/saas4ssi')


def oidc4vc_verifier_console_select(mode):
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    if request.method == 'GET':  
        my_list = db_api.list_oidc4vc_verifier()
        verifier_list = str()
        for data in my_list:
            data_dict = json.loads(data)
            id_token =  "Yes" if data_dict.get('id_token') == 'on' else 'No'
            vp_token =  "Yes" if data_dict.get('vp_token') == 'on' else 'No'
            try:
                curve = json.loads(data_dict['jwk']).get('crv')
            except Exception:
                curve = "Unknown"
            if not curve: curve = "RSA"
            client_id_scheme = data_dict.get('client_id_scheme', "Unknown")
            try:
                if data_dict['user'] == "all" or session['login_name'] in [data_dict['user'], "admin"]:
                    verifier = """<tr>
                        <td>""" + data_dict.get('application_name', "") + """</td>
                        <td>""" + data_dict.get('predefined_presentation_definition', "") + """</td>
                        <td>""" + client_id_scheme + """</td>
                        <td>""" + data_dict.get('profile', 'Unknwon') + """</td>
                        <td>""" + id_token + """</td>
                        <td>""" + vp_token + """</td>
                        <td>""" + curve + """</td>
                        <td><a href=/sandbox/verifier/console?client_id=""" + data_dict['client_id'] + """>""" + data_dict['client_id'] + """</a></td>
                    </tr>"""
                    verifier_list += verifier
            except Exception:
                pass
        return render_template('verifier_oidc/verifier_select.html', verifier_list=verifier_list, login_name=session['login_name']) 
    else:
        if request.form['button'] == "new":
            return redirect('/sandbox/verifier/console?client_id=' + db_api.create_oidc4vc_verifier(mode, user=session['login_name']))
        elif request.form['button'] == "logout":
            session.clear()
            return redirect('/sandbox/saas4ssi')
        elif request.form['button'] == "home":
            return render_template("menu.html", login_name=session["login_name"])
    

def oidc4vc_verifier_console(mode):
    global vc, reason

    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    if request.method == 'GET':
        if not request.args.get('client_id'):
            return redirect('/sandbox/verifier/console/select?user=' + session.get('login_name'))
        else:
            session['client_id'] = request.args.get('client_id')
        session['client_data'] = json.loads(db_api.read_oidc4vc_verifier(session['client_id']))
        
        if session['login_name'] == 'admin':
            verifier_page_list = oidc4vc_verifier_landing_page_style_list
        else:
            verifier_page_list = guest_oidc4vc_verifier_landing_page_style_list
            
        verifier_landing_page_style_select = str()
        for key, value in verifier_page_list.items():
            if key == session['client_data'].get('verifier_landing_page_style'):
                verifier_landing_page_style_select +=  "<option selected value=" + key + ">" + value + "</option>"
            else:
                verifier_landing_page_style_select +=  "<option value=" + key + ">" + value + "</option>"
        
        if session['login_name'] == "admin":
            credential_list = oidc4vc_verifier_credential_list
        else:
            credential_list = guest_oidc4vc_verifier_credential_list
            
        presentation_definition_uri_select = str()
        for key, value in predefined_presentation_uri_list.items():
            if key == session['client_data'].get('predefined_presentation_definition', 'None'):
                presentation_definition_uri_select +=  "<option selected value=" + key + ">" + value + "</option>"
            else:
                presentation_definition_uri_select +=  "<option value=" + key + ">" + value + "</option>"

        client_id_scheme_select = str()
        for key, value in client_id_scheme_list.items():
            if key == session['client_data'].get('client_id_scheme', 'None'):
                client_id_scheme_select +=  "<option selected value=" + key + ">" + value + "</option>"
            else:
                client_id_scheme_select +=  "<option value=" + key + ">" + value + "</option>"          

        # presentation definition calculation
        if session['client_data'].get('vp_token'):
            presentation_definition = str()
            
        if session['client_data'].get('vp_token'):
            try:
                presentation_definition = json.load(open(session['client_data'].get("predefined_presentation_definition") + '.json', 'r'))
            except Exception:  # fallback
                presentation_definition = json.load(open('presentation_definition/pid.json', 'r'))

        authorization_request = mode.server + 'sandbox/verifier/app/authorize?client_id=' + session['client_data']['client_id'] + "&scope=openid&response_type=code&redirect_uri=" +  session['client_data']['callback'] 
        implicit_request = mode.server + 'sandbox/verifier/app/authorize?client_id=' + session['client_data']['client_id'] + "&scope=openid&response_type=id_token&redirect_uri=" +  session['client_data']['callback']
        
        return render_template(
            'verifier_oidc/verifier_console.html',
            authorization_request=authorization_request,
            implicit_request=implicit_request,
            pkce="checked" if session['client_data'].get('pkce') else "",
            presentation_definition=json.dumps(presentation_definition, indent=4),
            id_token="checked" if session['client_data'].get('id_token')  else "",
            vp_token="checked" if session['client_data'].get('vp_token') else "",
            group="checked" if session['client_data'].get('group') else "",
            group_B="checked" if session['client_data'].get('group_B') else "",
            #filter_type_array="checked" if session['client_data'].get('filter_type_array') else "" ,
            presentation_definition_uri="checked" if session['client_data'].get('presentation_definition_uri') else "" ,
            client_metadata_uri="checked" if session['client_data'].get('client_metadata_uri') else "",
            jarm="checked" if session['client_data'].get('jarm') else "",
            request_uri_parameter_supported="checked" if session['client_data'].get('request_uri_parameter_supported') else "" ,
            request_parameter_supported="" if not session['client_data'].get('request_parameter_supported') else "checked" ,
            standalone="" if not session['client_data'].get('standalone')  else "checked" ,
            application_name=session['client_data'].get('application_name', ""),
            issuer=mode.server + "sandbox/verifier/app",
            client_id=session['client_data']['client_id'],
            client_secret=session['client_data']['client_secret'],
            token=mode.server + 'sandbox/verifier/app/token',
            page_title=session['client_data']['page_title'],
            page_subtitle=session['client_data']['page_subtitle'],
            authorization=mode.server + 'sandbox/verifier/app/authorize',
            logout=mode.server + 'sandbox/verifier/app/logout',
            userinfo=mode.server + 'sandbox/verifier/app/userinfo',
            verifier_landing_page_style_select=verifier_landing_page_style_select,
            presentation_definition_uri_select=presentation_definition_uri_select,
            client_id_scheme_select=client_id_scheme_select,
            login_name=session['login_name']
        )
    if request.method == 'POST':
        if request.form['button'] == "advanced":
            return redirect('/sandbox/verifier/console/advanced')
        
        elif request.form['button'] == "delete":
            db_api.delete_oidc4vc_verifier( request.form['client_id'])
            return redirect('/sandbox/verifier/console')

        elif request.form['button'] == "activity":
            return redirect('/sandbox/verifier/console/activity')
    
        elif request.form['button'] == "update":    
            if not request.form.get('id_token') and not request.form.get('vp_token'):
                flash("MUST add an id_token or a vp_token !", "warning")
                return redirect('/sandbox/verifier/console?client_id=' + request.form['client_id'])
            if request.form.get('group_B') and not request.form.get('vp_token') :
                flash("MUST check vp_token box !", "warning")
                return redirect('/sandbox/verifier/console?client_id=' + request.form['client_id'])
            if request.form.get('group') and not request.form.get('vp_token') :
                flash("MUST check vp_token box !", "warning")
                return redirect('/sandbox/verifier/console?client_id=' + request.form['client_id'])
            
            session['client_data']['standalone'] = request.form.get('standalone') 
            session['client_data']['pkce'] = request.form.get('pkce') 
            session['client_data']['id_token'] = request.form.get('id_token') 
            session['client_data']['vp_token'] = request.form.get('vp_token') 
            session['client_data']['presentation_definition_uri'] = request.form.get('presentation_definition_uri') 
            session['client_data']['client_metadata_uri'] = request.form.get('client_metadata_uri')
            session['client_data']['jarm'] = request.form.get('jarm')
            session['client_data']['request_uri_parameter_supported'] = request.form.get('request_uri_parameter_supported') 
            session['client_data']['request_parameter_supported'] = request.form.get('request_parameter_supported') 
            session['client_data']['application_name'] = request.form['application_name']
            session['client_data']['page_title'] = request.form['page_title']
            session['client_data']['page_subtitle'] = request.form['page_subtitle']
            session['client_data']['verifier_landing_page_style'] = request.form['verifier_landing_page_style']
            session['client_data']['client_id'] =  request.form['client_id']
            session['client_data']['client_secret'] = request.form['client_secret']

            session['client_data']['predefined_presentation_definition'] = request.form['predefined_presentation_definition']
            session['client_data']['client_id_scheme'] = request.form['client_id_scheme']
            
            db_api.update_oidc4vc_verifier(request.form['client_id'], json.dumps(session['client_data']))
            return redirect('/sandbox/verifier/console?client_id=' + request.form['client_id'])

        elif request.form['button'] == "copy":
            new_client_id =  db_api.create_oidc4vc_verifier(mode,  user=session['login_name'])
            new_data = copy.deepcopy(session['client_data'])
            new_data['application_name'] = new_data['application_name'] + ' (copie)'
            new_data['client_id'] = new_client_id
            new_data['user'] = session['login_name']
            db_api.update_oidc4vc_verifier(new_client_id, json.dumps(new_data))
            return redirect('/sandbox/verifier/console?client_id=' + new_client_id)


async def oidc4vc_verifier_advanced():
    global reason
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    if request.method == 'GET':
        session['client_data'] = json.loads(db_api.read_oidc4vc_verifier(session['client_id']))
        oidc4vc_profile_select = str()
        for key, value in oidc4vc_profile_list.items():
            if key ==  session['client_data'].get('profile', "DEFAULT"):
                oidc4vc_profile_select +=  "<option selected value=" + key + ">" + value + "</option>"
            else:
                oidc4vc_profile_select +=  "<option value=" + key + ">" + value + "</option>"      

        did = session['client_data'].get('did', "")
        did_document = oidc4vc.did_resolve_lp(did)
        try:
            jwk = json.dumps(json.loads(session['client_data']['jwk']), indent=4)
        except:
            jwk = "Key error"
        return render_template(
            'verifier_oidc/verifier_advanced.html',
            client_id=session['client_data']['client_id'],
            jwk=jwk,
            verification_method=session['client_data'].get('verification_method', ""),
            oidc4vc_profile_select=oidc4vc_profile_select,
            did=session['client_data'].get('did', ""),
            did_document=json.dumps(did_document, indent=4)
            )
    if request.method == 'POST':     
        session['client_data'] = json.loads(db_api.read_oidc4vc_verifier(session['client_id']))
        if request.form['button'] == "back":
            return redirect('/sandbox/verifier/console?client_id=' + request.form['client_id'])

        if request.form['button'] == "update":
            session['client_data']['profile'] = request.form['profile']
            session['client_data']['did'] = request.form['did']
            session['client_data']['verification_method'] = request.form['verification_method']
            try:
                did_method = request.form['did'].split(':')[1]
            except Exception:
                did_method = None
            
            if request.form['profile'] in ["EBSIV2", "EBSIV3"] and did_method != 'ebsi':
                flash("This profile requires did:ebsi", "warning")
                return redirect('/sandbox/verifier/console/advanced')
            
            elif request.form['profile'] == "GAIAX" and did_method != 'web':
                flash("This profile requires did:web", "warning")
                return redirect('/sandbox/verifier/console/advanced')

            elif request.form['profile'] == "JWTVC" and did_method not in ['web', 'ion']:
                flash("This profile requires did:web or did:ion", "warning")
                return redirect('/sandbox/verifier/console/advanced')
            else:
                session['client_data']['jwk'] = request.form['jwk']
                db_api.update_oidc4vc_verifier( request.form['client_id'], json.dumps(session['client_data']))
                return redirect('/sandbox/verifier/console/advanced')
        