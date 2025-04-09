from flask import jsonify,  redirect, request, render_template, redirect, session
import json
import db_api
import oidc4vc
import base64
from chatgpt import analyze_vp

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
    
    app.add_url_rule('/over18',  view_func=verifier_test_10, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_10',  view_func=verifier_test_10, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_11',  view_func=verifier_test_11, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_12',  view_func=verifier_test_12, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_13',  view_func=verifier_test_13, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/test_14',  view_func=verifier_test_14, methods=['GET'], defaults={'mode': mode})

    
    app.add_url_rule('/sandbox/verifier/callback',  view_func=verifier_callback, methods=['GET'])   
    app.add_url_rule('/sandbox/verifier/callback2',  view_func=verifier_callback2, methods=['GET'], defaults={'mode': mode})   
    app.add_url_rule('/sandbox/verifier/callback2_1',  view_func=verifier_callback2_1, methods=['GET'])
    app.add_url_rule('/sandbox/verifier/callback3',  view_func=verifier_callback3, methods=['GET'])

    
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
        verifier_id_test_10 = "qixvcqlwbq"
        verifier_id_test_11 = "icopdwkfhd"
        verifier_id_test_12 = "woxvjqkbrb"
        verifier_id_test_13 = "mnpqhqqrlw"
        verifier_id_test_14 = "cfjiehhlkn"

    else:
        verifier_id_test_1 = "rxukghiksb"
        verifier_id_test_2 = "paqqladucu"
        verifier_id_test_3 = "ybbiskyifx"
        verifier_id_test_4 = "gbypcbxtum"
        verifier_id_test_5 = "iddznwujyy"
        verifier_id_test_6 = "ejqwxtjdlu"
        verifier_id_test_7 = "ypsfdlfoti"
        verifier_id_test_8 = "uxcdccjhmq"
        verifier_id_test_9 = "zvuzyxjhjk"
        verifier_id_test_10 = "ifdpawlhsw"
        verifier_id_test_11 = "pvtrczpaeg"
        verifier_id_test_12 = "fzqtmovhto"
        verifier_id_test_13 = "nyudzjxuhj"
        verifier_id_test_14 = "frrrgvvtdt"


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
    
    title_test_10 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_10))["page_title"]
    subtitle_test_10 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_10))["page_subtitle"]
    
    title_test_11 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_11))["page_title"]
    subtitle_test_11 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_11))["page_subtitle"]
    title_test_12 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_12))["page_title"]
    subtitle_test_12 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_12))["page_subtitle"]
    title_test_13 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_13))["page_title"]
    subtitle_test_13 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_13))["page_subtitle"]
    title_test_14 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_14))["page_title"]
    subtitle_test_14 = json.loads(db_api.read_oidc4vc_verifier(verifier_id_test_14))["page_subtitle"]


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
        title_test_10=title_test_10,
        subtitle_test_10=subtitle_test_10,
        title_test_11=title_test_11,
        subtitle_test_11=subtitle_test_11,
        title_test_12=title_test_12,
        subtitle_test_12=subtitle_test_12,
        title_test_13=title_test_13,
        subtitle_test_13=subtitle_test_13,
        title_test_14=title_test_14,
        subtitle_test_14=subtitle_test_14

    )


def verifier_test_1(mode): # Tezos EBSI
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "fofadhfrez"
        else:
            client_id = "rxukghiksb"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&nonce=100&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400


def verifier_test_3(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "rxbypnwhxc"
        else:
            client_id = "ybbiskyifx"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&nonce=100&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400


def verifier_test_2(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "wvjotpxxrd"
        else:
            client_id = "paqqladucu"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400


def verifier_test_4(mode): 
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "iftsntwcyl"
        else:
            client_id = "gbypcbxtum"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&nonce=500&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400


def verifier_test_5(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "xpkhvsemfd"
        else:
            client_id = "iddznwujyy"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&scope=SMS:33607182594&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400


def verifier_test_6(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "zkzkwshdns"
        else:
            client_id = "ejqwxtjdlu"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400


def verifier_test_7(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "feyfeamejt"
        else:
            client_id = "ypsfdlfoti"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400


def verifier_test_8(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "novanyhlhs"
        else:
            client_id = "uxcdccjhmq"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400
    

def verifier_test_9(mode):
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "rkubsscrkt"
        else:
            client_id = "zvuzyxjhjk"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
        return redirect(url)
    else:
        return jsonify("Unauthorized"), 400


def verifier_test_10(mode):
    session['verified'] = False
    if mode.myenv == 'aws':
        client_id = "qixvcqlwbq"
    else:
        client_id = "ifdpawlhsw"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
    return redirect(url)


def verifier_test_11(mode):
    session['verified'] = False
    if mode.myenv == 'aws':
        client_id = "icopdwkfhd"
    else:
        client_id = "pvtrczpaeg"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
    return redirect(url)


def verifier_test_12(mode):
    session['verified'] = False
    if mode.myenv == 'aws':
        client_id = "woxvjqkbrb"
    else:
        client_id = "fzqtmovhto"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
    return redirect(url)


def verifier_test_13(mode):
    session['verified'] = False
    if mode.myenv == 'aws':
        client_id = "mnpqhqqrlw"
    else:
        client_id = "nyudzjxuhj"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
    return redirect(url)


def verifier_test_14(mode):
    session['verified'] = False
    if mode.myenv == 'aws':
        client_id = "cfjiehhlkn"
    else:
        client_id = "frrrgvvtdt"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
    return redirect(url)


def verifier_callback():
    return jsonify(request.args)


# for sd-jwt
def verifier_callback3():
    if request.args.get("error"):
        return jsonify(request.args)
    token = request.args.get("id_token")
    presentation_submission = request.args.get("presentation_submission")
    if presentation_submission == "null":
        token =  request.args.get("wallet_id_token")
        return jsonify(
            {
                "header": oidc4vc.get_header_from_token(token),
                "payload": oidc4vc.get_payload_from_token(token)
            })
    #vcsd = oidc4vc.get_payload_from_token(token)['vc+sd-jwt'].split("~")
    vcsd = token.split("~")
    vcsd_jwt_payload = oidc4vc.get_payload_from_token(vcsd[0])
    vcsd_jwt_header = oidc4vc.get_header_from_token(vcsd[0])
    disclosure = ""
    if not vcsd[-1]:
        len_vcsd = len(vcsd)
        kbjwt_header = kbjwt_payload = "No KB"
    else:
        len_vcsd = len(vcsd)-1
        kbjwt_header = oidc4vc.get_header_from_token(vcsd[-1])
        kbjwt_payload = oidc4vc.get_payload_from_token(vcsd[-1])
    for i in range(1, len_vcsd):
        _disclosure = vcsd[i]
        _disclosure += "=" * ((4 - len(vcsd[i]) % 4) % 4)    
        print(_disclosure)
        disclosure += "\r\n" + base64.urlsafe_b64decode(_disclosure.encode()).decode()
    ia_analyze = analyze_vp(token)
    return render_template(
        'verifier_oidc/vcsd_jwt_test.html',
        raw=token,
        presentation_submission=json.dumps(presentation_submission, indent=4),
        vcsd_jwt_header=json.dumps(vcsd_jwt_header, indent=4),
        vcsd_jwt_payload=json.dumps(vcsd_jwt_payload, indent=4),
        disclosure=disclosure,
        kbjwt_header=json.dumps(kbjwt_header, indent=4),
        kbjwt_payload=json.dumps(kbjwt_payload, indent=4),
        ia_analyse=ia_analyze
        )


def verifier_callback2(mode):
    return redirect('/sandbox/verifier/app/logout' + '?post_logout_redirect_uri=' + mode.server + "sandbox/verifier/callback2_1")


def verifier_callback2_1():
    return render_template('face2face.html')