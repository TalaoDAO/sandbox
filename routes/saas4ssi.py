from flask import jsonify, request, render_template, redirect, session, flash, send_file
import base64
import json
import db_user_api
import op_constante
import logging
import message
from werkzeug.utils import secure_filename

logging.basicConfig(level=logging.INFO)


admin_list = ["thierry.thevenet@talao.io", "nicolas.muller@talao.io", "hugo@altme.io", "googandads@gmail.com"]


def init_app(app,red, mode):
    
    #@app.add_url_rule('/sandbox/static/<filename>', methods=['GET'])
    app.add_url_rule('/',  view_func=saas_home, methods=['GET', 'POST'])
    app.add_url_rule('/sandbox',  view_func=saas_home, methods=['GET', 'POST'])
    app.add_url_rule('/sandbox/saas4ssi',  view_func=saas_home, methods=['GET', 'POST'])
    
    app.add_url_rule('/sandbox/saas4ssi/dids',  view_func=dids, methods=['GET'])
    app.add_url_rule('/sandbox/saas4ssi/menu',  view_func=saas_menu, methods=['GET', 'POST'])
    
    app.add_url_rule('/sandbox/saas4ssi/login_2',  view_func=saas_login_2, methods=['GET', 'POST'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/saas4ssi/signup',  view_func=saas_signup, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/saas4ssi/admin',  view_func=admin, methods=['GET', 'POST'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/saas4ssi/callback_4',  view_func=saas_callback_4, methods=['GET', 'POST'], defaults={'mode': mode}) # signup ebsi v3

    
    app.add_url_rule('/sandbox/saas4ssi/callback_3',  view_func=saas_callback_3, methods=['GET', 'POST']) # login with ebsi v3 

    app.add_url_rule('/sandbox/saas4ssi/logout',  view_func=saas_logout, methods = ['GET', 'POST'])

    return





def saas_home():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        logging.info('remote IP = %s', request.environ['REMOTE_ADDR'])
    else:
        logging.info('remote IP = %s', request.environ['HTTP_X_FORWARDED_FOR'])  # if behind a proxy
    return render_template("home.html")


def dids():
    return render_template("dids.html")


def saas_menu():
    if not session.get('is_connected') or not session.get('login_name'):
        return redirect('/sandbox/saas4ssi')
    return render_template("menu.html", login_name=session["login_name"])


def saas_logout():
    session.clear()
    return redirect("/sandbox/saas4ssi")


def saas_login_2(mode):
    session.clear()
    if mode.myenv == 'aws':
        client_id = "pppbfvflvu"
    else: 
        mode.server == "http://192.168.0.65:3000/"
        client_id = "hzohfwaxcp"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/saas4ssi/callback_3"
    return redirect(url)


def saas_signup(mode):
    if mode.myenv == 'aws':
        client_id = "nveyccqfoq"
    else:
        mode.server == "http://192.168.0.65:3000/"
        client_id = "nkkxhmxxhw"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/saas4ssi/callback_4"
    return redirect(url)


def admin(mode):
    if request.method == "GET":
        return render_template("admin.html")
    
    if request.form['secret'] == mode.admin:
        session['is_connected'] = True
        session['login_name'] = 'admin'
        return render_template("menu.html", login_name=session["login_name"])
    else:
        return redirect("/sandbox/saas4ssi")


# Register with EBSI v3
def saas_callback_4(mode):
    if request.args.get("error"):
        logging.warning("access denied")
        session.clear()
        return redirect("/sandbox/saas4ssi")
    id_token = request.args['id_token']
    s = id_token.split('.')[1]
    payload = base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4)) 
    login_name = json.loads(payload.decode())['sub']
    if not db_user_api.read(login_name):
        data = op_constante.user
        data["did"] = json.loads(payload.decode())['sub']
        data['login_name'] = session['login_name'] = login_name
        session['is_connected'] = True
        db_user_api.create(login_name, data)
        try:
            message.message("Registration on Saas Altme of " + login_name , "thierry@altme.io", "New user = " + login_name, mode)
        except Exception:
            pass
        return redirect('/sandbox/saas4ssi/menu')
    else:
        logging.warning('user already exists')
        flash("You are already registered, you can login !", "warning")
        return redirect("/sandbox/saas4ssi")

    
# login
def saas_callback_3():
    if request.args.get("error"):
        logging.warning("access denied")
        session.clear()
        return redirect("/sandbox/saas4ssi")
    id_token = request.args['id_token']
    s = id_token.split('.')[1]
    payload = base64.urlsafe_b64decode(s + '=' * (4 - len(s) % 4))
    login_name = json.loads(payload.decode())['sub']
    if login_name in admin_list:
        session['login_name'] = "admin"
        session['is_connected'] = True
        return redirect('/sandbox/saas4ssi/menu')
    elif db_user_api.read(login_name):
        session['login_name'] = login_name
        session['is_connected'] = True
        return redirect('/sandbox/saas4ssi/menu')
    else:
        logging.warning('error, user does not exist')
        session.clear()
        return render_template("access_denied.html")
