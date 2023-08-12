from flask import  request, render_template, redirect, session, flash
import json
import copy
import logging
import db_api 
from profile import profile
import oidc4vc
import pex
from oidc4vc_constante import ebsi_verifier_credential_list
from oidc4vc_constante import ebsi_verifier_landing_page_style_list, oidc4vc_profile_list
from oidc4vc_constante import type_2_schema

logging.basicConfig(level=logging.INFO)

did_selected = 'did:tz:tz2NQkPq3FFA3zGAyG8kLcWatGbeXpHMu7yk'

def init_app(app,red, mode) :
    app.add_url_rule('/sandbox/ebsi/verifier/console/logout',  view_func=ebsi_verifier_console_logout, methods = ['GET', 'POST'])
    app.add_url_rule('/sandbox/ebsi/verifier/console',  view_func=ebsi_verifier_console, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/verifier/console/select',  view_func=ebsi_verifier_console_select, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/ebsi/verifier/console/advanced',  view_func=ebsi_verifier_advanced, methods = ['GET', 'POST'])

    #app.add_url_rule('/sandbox/ebsi/verifier/preview_presentation/<stream_id>',  view_func=ebsi_verifier_preview_presentation_endpoint, methods = ['GET', 'POST'],  defaults={'red' : red})

      # nav bar option
    app.add_url_rule('/sandbox/ebsi/verifier/nav/logout',  view_func=ebsi_verifier_nav_logout, methods = ['GET'])
    app.add_url_rule('/sandbox/ebsi/verifier/nav/create',  view_func=ebsi_verifier_nav_create, methods = ['GET'], defaults= {'mode' : mode})
    return

      
def ebsi_verifier_nav_logout() :
    if not session.get('is_connected') or not session.get('login_name') :
        return redirect('/sandbox/saas4ssi')
    session.clear()
    return redirect ('/sandbox/saas4ssi')


def ebsi_verifier_nav_create(mode) :
    if not session.get('is_connected') or not session.get('login_name') :
        return redirect('/sandbox/saas4ssi')
    return redirect('/sandbox/ebsi/verifier/console?client_id=' + db_api.create_ebsi_verifier(mode, user=session['login_name']))

 
def ebsi_verifier_console_logout():
    if session.get('is_connected') :
        session.clear()
    return redirect('/sandbox/saas4ssi')


def ebsi_verifier_console_select(mode) :
    if not session.get('is_connected') or not session.get('login_name') :
        return redirect('/sandbox/saas4ssi')
    if request.method == 'GET' :  
        my_list = db_api.list_ebsi_verifier()
        verifier_list=str()
        for data in my_list :
            data_dict = json.loads(data)
            id_token =  "Yes" if data_dict.get('id_token') == 'on' else 'No'
            vp_token =  "Yes" if data_dict.get('vp_token') == 'on' else 'No'
            group =  "Yes" if data_dict.get('group') == 'on' else 'No'
            try :
                if data_dict['user'] == "all" or session['login_name'] in [data_dict['user'], "admin"] :
                    verifier = """<tr>
                        <td>""" + data_dict.get('application_name', "") + """</td>
                        <td>""" + data_dict['user'] + """</td>
                        <td>""" + ebsi_verifier_credential_list.get(data_dict.get('vc_1', 'Unknown'), "unknown") + """</td>
                        <td>""" + ebsi_verifier_credential_list.get(data_dict['vc_2'], "unknown") + """</td>
                        <td>""" + data_dict.get('profile', 'Unknwon') + """</td>
                        <td>""" + id_token + """</td>
                        <td>""" + vp_token + """</td>
                        <td>""" + group + """</td>
                        <td><a href=/sandbox/ebsi/verifier/console?client_id=""" + data_dict['client_id'] + """>""" + data_dict['client_id'] + """</a></td>
                    </tr>"""
                    verifier_list += verifier
            except :
                pass
        return render_template('ebsi/ebsi_verifier_select.html', verifier_list=verifier_list, login_name=session['login_name']) 
    else :
        if request.form['button'] == "new" :
            return redirect('/sandbox/ebsi/verifier/console?client_id=' + db_api.create_ebsi_verifier(mode, user=session['login_name']))
        elif request.form['button'] == "logout" :
            session.clear()
            return redirect ('/sandbox/saas4ssi')
        elif request.form['button'] == "home" :
            return render_template("menu.html", login_name=session["login_name"])
    

def ebsi_verifier_console(mode) :
    global vc, reason
  
    if not session.get('is_connected') or not session.get('login_name') :
        return redirect('/sandbox/saas4ssi')
    if request.method == 'GET' :
        if not request.args.get('client_id') :
            return redirect('/sandbox/ebsi/verifier/console/select?user='+ session.get('login_name'))
        else  :
            session['client_id'] = request.args.get('client_id')
        session['client_data'] = json.loads(db_api.read_ebsi_verifier(session['client_id']))
        
        verifier_landing_page_style_select = str()
        for key, value in ebsi_verifier_landing_page_style_list.items() :
                if key == session['client_data'].get('verifier_landing_page_style') :
                    verifier_landing_page_style_select +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    verifier_landing_page_style_select +=  "<option value=" + key + ">" + value + "</option>"

        vc_select_1 = str()
        for key, value in ebsi_verifier_credential_list.items() :
                if key ==   session['client_data'].get('vc_1', 'DID') :
                    vc_select_1 +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select_1 +=  "<option value=" + key + ">" + value + "</option>"
        vc_select_2 = str()
        for key, value in ebsi_verifier_credential_list.items() :
                if key ==   session['client_data'].get('vc_2', "DID") :
                    vc_select_2 +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select_2 +=  "<option value=" + key + ">" + value + "</option>"
        vc_select_3 = str()
        for key, value in ebsi_verifier_credential_list.items() :
                if key ==   session['client_data'].get('vc_3', "DID") :
                    vc_select_3 +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select_3 +=  "<option value=" + key + ">" + value + "</option>"
        vc_select_4 = str()
        for key, value in ebsi_verifier_credential_list.items() :
                if key ==   session['client_data'].get('vc_4', "DID") :
                    vc_select_4 +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select_4 +=  "<option value=" + key + ">" + value + "</option>"

        # for group
        vc_select_5 = str()
        for key, value in ebsi_verifier_credential_list.items() :
                if key ==   session['client_data'].get('vc_5', 'DID') :
                    vc_select_5 +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select_5 +=  "<option value=" + key + ">" + value + "</option>"
        
        vc_select_6 = str()
        for key, value in ebsi_verifier_credential_list.items() :
                if key ==   session['client_data'].get('vc_6', "DID") :
                    vc_select_6 +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select_6 +=  "<option value=" + key + ">" + value + "</option>"
        vc_select_7 = str()
        for key, value in ebsi_verifier_credential_list.items() :
                if key ==   session['client_data'].get('vc_7', "DID") :
                    vc_select_7 +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select_7 +=  "<option value=" + key + ">" + value + "</option>"
        vc_select_8 = str()
        for key, value in ebsi_verifier_credential_list.items() :
                if key ==   session['client_data'].get('vc_8', "DID") :
                    vc_select_8 +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    vc_select_8 +=  "<option value=" + key + ">" + value + "</option>"
        
        # presentation definition calculation
        presentation_definition = str()
        if session['client_data'].get('vp_token'):    
            prez = pex.Presentation_Definition(session['client_data']['application_name'], "Altme presentation definition subset of PEX v2.0")  
            for i in ["1", "2", "3", "4"] :
                vc = 'vc_' + i
                reason = 'reason_' + i
                if session['client_data'][vc] != 'None'   :
                    if session['client_data']['profile'] == "EBSI-V2" :
                        prez.add_constraint("$.credentialSchema.id", type_2_schema[session['client_data'][vc]], "Input descriptor for credential " + i , session['client_data'][reason])
                    else :
                        prez.add_constraint("$.credentialSubject.type",  session['client_data'][vc], "Input descriptor for credential " + i, session['client_data'][reason])
            if session['client_data'].get('group') : 
                prez.add_group("Group A", "A")
                for i in ["5", "6", "7", "8"] :
                    vc = 'vc_' + i
                    if session['client_data'][vc] != 'None'   :
                        if session['client_data']['profile'] == "EBSI-V2" :
                            prez.add_constraint_with_group("$.credentialSchema.id", type_2_schema[session['client_data'][vc]], "Input descriptor for credential " + i, "", "A")
                        else :
                            prez.add_constraint_with_group("$.credentialSubject.type",  session['client_data'][vc], "Input descriptor for credential " + i, "", "A")
            
            if profile[session['client_data']['profile']]["verifier_vp_type"] == 'ldp_vp' :
                prez.add_format_ldp_vp()
                prez.add_format_ldp_vc()
            if profile[session['client_data']['profile']]["verifier_vp_type"] == 'jwt_vp' :
                prez.add_format_jwt_vp()
                prez.add_format_jwt_vc()
            
            presentation_definition = prez.get()



        authorization_request = mode.server + 'sandbox/ebsi/authorize?client_id=' + session['client_data']['client_id'] + "&scope=openid&response_type=code&redirect_uri=" +  session['client_data']['callback'] 
        implicit_request = mode.server + 'sandbox/ebsi/authorize?client_id=' + session['client_data']['client_id'] + "&scope=openid&response_type=id_token&redirect_uri=" +  session['client_data']['callback']
        return render_template('ebsi/ebsi_verifier_console.html',
                authorization_request = authorization_request,
                implicit_request = implicit_request,
                title = session['client_data'].get('title'),
                pkce = "" if session['client_data'].get('pkce') in [None, False]  else "checked" ,
                presentation_definition=json.dumps(presentation_definition, indent=4),
                id_token = "" if session['client_data'].get('id_token') in [None, False]  else "checked" ,
                vp_token = "" if session['client_data'].get('vp_token') in [None, False]  else "checked" ,
                group = "" if session['client_data'].get('group') in [None, False]  else "checked" ,
                request_uri = "" if session['client_data'].get('request_uri') in [None, False]  else "checked" ,
                standalone = "" if session['client_data'].get('standalone') in [None, False]  else "checked" ,
                application_name = session['client_data'].get('application_name', ""),
                contact_name = session['client_data'].get('contact_name'),
                contact_email = session['client_data'].get('contact_email'),
                issuer = mode.server + "sandbox/ebsi",
                client_id= session['client_data']['client_id'],
                client_secret= session['client_data']['client_secret'],
                token=mode.server + 'sandbox/ebsi/token',
                page_title = session['client_data']['page_title'],
                note = session['client_data']['note'],
                page_subtitle = session['client_data']['page_subtitle'],
                page_description = session['client_data']['page_description'],
                authorization=mode.server + 'sandbox/ebsi/authorize',
                logout=mode.server + 'sandbox/ebsi/logout',
                userinfo=mode.server + 'sandbox/ebsi/userinfo',
                company_name = session['client_data']['company_name'],
                reason_1 = session['client_data'].get('reason_1', ""),
                reason_2 = session['client_data'].get('reason_2'),
                reason_3 = session['client_data'].get('reason_3', ""),
                reason_4 = session['client_data'].get('reason_4', ""),
                qrcode_message = session['client_data'].get('qrcode_message', ""),
                mobile_message = session['client_data'].get('mobile_message', ""),
                user_name=session['client_data'].get('user'),
                verifier_landing_page_style_select =  verifier_landing_page_style_select,
                vc_select_1=vc_select_1,
                vc_select_2=vc_select_2,
                vc_select_3=vc_select_3,
                vc_select_4=vc_select_4,
                vc_select_5=vc_select_5,
                vc_select_6=vc_select_6,
                vc_select_7=vc_select_7,
                vc_select_8=vc_select_8,
                login_name=session['login_name']
                )
    if request.method == 'POST' :
        if request.form['button'] == "advanced" :
            return redirect ('/sandbox/ebsi/verifier/console/advanced')
        
        elif request.form['button'] == "delete" :
            db_api.delete_ebsi_verifier( request.form['client_id'])
            return redirect ('/sandbox/ebsi/verifier/console')

        elif request.form['button'] == "activity" :
            return redirect ('/sandbox/ebsi/verifier/console/activity')
      
        elif request.form['button'] == "update" :
            
            if not request.form.get('id_token') and not request.form.get('vp_token')  :
                flash("MUST add an id_token or a vp_token !", "warning")
                return redirect('/sandbox/ebsi/verifier/console?client_id=' + request.form['client_id'])
            if request.form.get('vp_token') and not request.form.get('group') :
                if request.form['vc_1'] == 'None' and request.form['vc_2'] == 'None' and request.form['vc_3'] == 'None' and request.form['vc_4'] == 'None' and not request.form.get('group') :
                    flash("MUST add a credential !", "warning")
                    return redirect('/sandbox/ebsi/verifier/console?client_id=' + request.form['client_id'])
            if request.form.get('group') and request.form.get('vp_token') :
                nb = 0
                for i in ["5", "6", "7", "8"] :
                    vc = 'vc_' + i  
                    if request.form.get(vc) != 'None' :
                        nb += 1
                if nb < 2 :
                    flash("MUST add at minimum 2 credentials to setup a Group !", "warning")
                    return redirect('/sandbox/ebsi/verifier/console?client_id=' + request.form['client_id'])

            session['client_data']['note'] = request.form['note']
            session['client_data']['standalone'] = request.form.get('standalone') 
            session['client_data']['pkce'] = request.form.get('pkce') 
            session['client_data']['id_token'] = request.form.get('id_token') 
            session['client_data']['vp_token'] = request.form.get('vp_token') 
            session['client_data']['group'] = request.form.get('group') 
            session['client_data']['request_uri'] = request.form.get('request_uri') 
            session['client_data']['application_name'] = request.form['application_name']
            session['client_data']['page_title'] = request.form['page_title']
            session['client_data']['page_subtitle'] = request.form['page_subtitle']
            session['client_data']['page_description'] = request.form['page_description']
            session['client_data']['contact_name'] = request.form['contact_name']
            session['client_data']['title'] = request.form['title'] 
            session['client_data']['verifier_landing_page_style'] = request.form['verifier_landing_page_style']
            session['client_data']['contact_email'] = request.form['contact_email']
            session['client_data']['client_id'] =  request.form['client_id']
            session['client_data']['client_secret'] = request.form['client_secret']
            session['client_data']['company_name'] = request.form['company_name']
            
            session['client_data']['reason_1'] = request.form['reason_1']
            session['client_data']['reason_2'] = request.form['reason_2']
            session['client_data']['reason_3'] = request.form['reason_3']
            session['client_data']['reason_4'] = request.form['reason_4']
           
            session['client_data']['vc_1'] = request.form['vc_1']
            session['client_data']['vc_2'] = request.form['vc_2']
            session['client_data']['vc_3'] = request.form['vc_3']
            session['client_data']['vc_4'] = request.form['vc_4']
            session['client_data']['vc_5'] = request.form['vc_5']
            session['client_data']['vc_6'] = request.form['vc_6']
            session['client_data']['vc_7'] = request.form['vc_7']
            session['client_data']['vc_8'] = request.form['vc_8']

            session['client_data']['user'] = request.form['user_name']
            session['client_data']['qrcode_message'] = request.form['qrcode_message']
            session['client_data']['mobile_message'] = request.form['mobile_message']  

            if not request.form.get('vp_token') and session['client_data']['group'] :
                flash("MUST select vp_token to use group !", "warning")
                session['client_data']['group'] = None        
            
            db_api.update_ebsi_verifier(request.form['client_id'], json.dumps(session['client_data']))
            return redirect('/sandbox/ebsi/verifier/console?client_id=' + request.form['client_id'])

        elif request.form['button'] == "copy" :
            new_client_id=  db_api.create_ebsi_verifier(mode,  user=session['login_name'])
            new_data = copy.deepcopy(session['client_data'])
            new_data['application_name'] = new_data['application_name'] + ' (copie)'
            new_data['client_id'] = new_client_id
            new_data['user'] = session['login_name']
            db_api.update_ebsi_verifier(new_client_id, json.dumps(new_data))
            return redirect('/sandbox/ebsi/verifier/console?client_id=' + new_client_id)
 

async def ebsi_verifier_advanced() :
    global  reason
    if not session.get('is_connected') or not session.get('login_name') :
        return redirect('/sandbox/saas4ssi')
    if request.method == 'GET' :
        session['client_data'] = json.loads(db_api.read_ebsi_verifier(session['client_id']))
        oidc4vc_profile_select = str()
        for key, value in oidc4vc_profile_list.items() :
                if key ==  session['client_data'].get('profile', "DEFAULT") :
                    oidc4vc_profile_select +=  "<option selected value=" + key + ">" + value + "</option>"
                else :
                    oidc4vc_profile_select +=  "<option value=" + key + ">" + value + "</option>"      

        did = session['client_data'].get('did', "")
        did_document = oidc4vc.did_resolve_lp(did)
        jwk = json.dumps(json.loads(session['client_data']['jwk']), indent=4)
      
        return render_template('ebsi/ebsi_verifier_advanced.html',
                client_id = session['client_data']['client_id'],
                jwk = jwk,
                verification_method = session['client_data'].get('verification_method', ""),
                oidc4vc_profile_select=oidc4vc_profile_select,
                did = session['client_data'].get('did', ""),
                did_document=json.dumps(did_document, indent=4)
                )
    if request.method == 'POST' :     
        session['client_data'] = json.loads(db_api.read_ebsi_verifier(session['client_id']))
        if request.form['button'] == "back" :
            return redirect('/sandbox/ebsi/verifier/console?client_id=' + request.form['client_id'])

        if request.form['button'] == "update" :
            session['client_data']['profile'] = request.form['profile']
            session['client_data']['did'] = request.form['did']
            session['client_data']['verification_method'] = request.form['verification_method']
            try :
                did_method = request.form['did'].split(':')[1]
            except :
                did_method = None
            
            if request.form['profile'] in ["EBSIV2", "EBSIV3"] and did_method != 'ebsi' :
                flash("This profile requires did:ebsi", "warning")
                return redirect('/sandbox/ebsi/verifier/console/advanced')
            
            elif request.form['profile'] == "GAIAX" and did_method != 'web' :
                flash("This profile requires did:web", "warning")
                return redirect('/sandbox/ebsi/verifier/console/advanced')

            elif request.form['profile'] == "JWTVC" and did_method not in ['web', 'ion'] :
                flash("This profile requires did:web or did:ion", "warning")
                return redirect('/sandbox/ebsi/verifier/console/advanced')
            
            else:
                session['client_data']['jwk'] = request.form['jwk']
                db_api.update_ebsi_verifier( request.form['client_id'], json.dumps(session['client_data']))
                return redirect('/sandbox/ebsi/verifier/console/advanced')
          