from flask import jsonify,  redirect, request, render_template
import json
import db_api

def init_app(app,red, mode):
    app.add_url_rule('/sandbox/verifier/test_1',  view_func=verifier_test_1, methods=['GET'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/verifier/test_3',  view_func=verifier_test_3, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_2',  view_func=verifier_test_2, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_4',  view_func=verifier_test_4, methods=['GET'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/verifier/test_5',  view_func=verifier_test_5, methods=['GET'], defaults={'mode': mode}) # test 9
    app.add_url_rule('/sandbox/verifier/test_6',  view_func=verifier_test_6, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_7',  view_func=verifier_test_7, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_8',  view_func=verifier_test_8, methods=['GET'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/verifier/test_9',  view_func=verifier_test_9, methods=['GET'], defaults={'mode': mode})
    
    
    
    app.add_url_rule('/sandbox/verifier/callback',  view_func=verifier_callback, methods=['GET'])   
    
    # Test
    app.add_url_rule('/sandbox/verifier/oidc/test',  view_func=verifier_oidc_test, methods=['GET', 'POST'], defaults={'mode': mode})


def verifier_oidc_test(mode):
    if mode.myenv == 'aws':
        verifier_id_test_1 = "fofadhfrez"
        verifier_id_test_2 = "wvjotpxxrd"
        verifier_id_test_3 = "rxbypnwhxc"
        verifier_id_test_4 = "iftsntwcyl"
        verifier_id_test_5 = "xpkhvsemfd"
        verifier_id_test_6 = "zkzkwshdns"
        verifier_id_test_7 = "feyfeamejt"
        verifier_id_test_8 = "novanyhlhs"
        verifier_id_test_9 = "rkubsscrkt"
        verifier_id_test_10 = ""
        verifier_id_test_11 = ""
    else:
        verifier_id_test_1 = "rxukghiksb"
        verifier_id_test_2 = "ybbiskyifx"
        verifier_id_test_3 = "ybbiskyifx"
        verifier_id_test_4 = "gbypcbxtum"
        verifier_id_test_5 = "iddznwujyy"
        verifier_id_test_6 = "ejqwxtjdlu"
        verifier_id_test_7 = "ypsfdlfoti"
        verifier_id_test_8 = "uxcdccjhmq"
        verifier_id_test_9 = "zvuzyxjhjk"
        verifier_id_test_10 = ""
        verifier_id_test_11 = ""
        
    title_test_1 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_1))["page_title"]
    subtitle_test_1 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_1))["page_subtitle"]
    title_test_2 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_2))["page_title"]
    subtitle_test_2 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_2))["page_subtitle"]
    title_test_3 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_3))["page_title"]
    subtitle_test_3 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_3))["page_subtitle"]
    title_test_4 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_4))["page_title"]
    subtitle_test_4 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_4))["page_subtitle"]
    title_test_5 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_5))["page_title"]
    subtitle_test_5 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_5))["page_subtitle"]
    title_test_6 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_6))["page_title"]
    subtitle_test_6 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_6))["page_subtitle"]
    title_test_7 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_7))["page_title"]
    subtitle_test_7 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_7))["page_subtitle"]
    title_test_8 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_8))["page_title"]
    subtitle_test_8 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_8))["page_subtitle"]
    title_test_9 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_9))["page_title"]
    subtitle_test_9 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_9))["page_subtitle"]
    #title_test_10 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_10))["page_title"]
    #subtitle_test_10 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_10))["page_subtitle"]
    #title_test_11 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_11))["page_title"]
    #subtitle_test_11 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_11))["page_subtitle"]

    return render_template(
        'verifier_oidc/wallet_verifier_test.html',
        title_test_1=title_test_1,
        subtitle_test_1=subtitle_test_1,
        title_test_2=title_test_2,
        subtitle_test_2=subtitle_test_2,
        title_test_3=title_test_3,
        subtitle_test_3=subtitle_test_3,
        title_test_4=title_test_4,
        subtitle_test_4=subtitle_test_4,
        title_test_5=title_test_5,
        subtitle_test_5=subtitle_test_5,
        title_test_6=title_test_6,
        subtitle_test_6=subtitle_test_6,
        title_test_7=title_test_7,
        subtitle_test_7=subtitle_test_7,
        title_test_8=title_test_8,
        subtitle_test_8=subtitle_test_8,
        title_test_9=title_test_9,
        subtitle_test_9=subtitle_test_9,
        #title_test_10=title_test_10,
        #subtitle_test_10=subtitle_test_10,
        #title_test_11=title_test_11,
        #subtitle_test_11=subtitle_test_11
    )

def verifier_test_1(mode): # Tezos EBSI
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "fofadhfrez"
        else:
            client_id = "rxukghiksb"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&nonce=100&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_test_3(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "rxbypnwhxc"
        else:
            client_id = "ybbiskyifx"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&nonce=100&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_test_2(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "wvjotpxxrd"
        else:
            client_id = "paqqladucu"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_test_4(mode): 
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "iftsntwcyl"
        else:
            client_id = "gbypcbxtum"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&nonce=500&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_test_5(mode): # Test 9
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "xpkhvsemfd"
        else:
            client_id = "iddznwujyy"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_test_6(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "zkzkwshdns"
        else:
            client_id = "ejqwxtjdlu"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_test_7(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "feyfeamejt"
        else:
            client_id = "ypsfdlfoti"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_test_8(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "novanyhlhs"
        else:
            client_id = "uxcdccjhmq"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    

def verifier_test_9(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "rkubsscrkt"
        else:
            client_id = "zvuzyxjhjk"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_callback():
    return jsonify(request.args)