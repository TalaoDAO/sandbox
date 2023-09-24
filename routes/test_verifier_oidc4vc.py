from flask import jsonify,  redirect, request


def init_app(app,red, mode):
    app.add_url_rule('/sandbox/verifier/tezos-ebsi',  view_func=verifier_tezos_ebsi, methods=['GET'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/verifier/default',  view_func=verifier_default, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/default_2',  view_func=verifier_default_2, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/default_3',  view_func=verifier_default_3, methods=['GET'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/verifier/gaiax',  view_func=verifier_gaiax, methods=['GET'], defaults={'mode': mode}) # test 9
    app.add_url_rule('/sandbox/verifier/gaiax_2',  view_func=verifier_gaiax_2, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/gaiax_3',  view_func=verifier_gaiax_3, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/ebsiv3',  view_func=verifier_ebsiv3, methods=['GET'], defaults={'mode': mode})

    app.add_url_rule('/sandbox/verifier/ebsiv3_2',  view_func=verifier_ebsiv3_2, methods=['GET'], defaults={'mode': mode})
    app.add_url_rule('/sandbox/verifier/callback',  view_func=verifier_callback, methods=['GET'])   


def verifier_tezos_ebsi(mode): # Tezos EBSI
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "fofadhfrez"
        else:
            client_id = "rxukghiksb"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&nonce=100&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_default(mode): # Test 3
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "rxbypnwhxc"
        else:
            client_id = "ybbiskyifx"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&nonce=100&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_default_2(mode): # Test 4
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "wvjotpxxrd"
        else:
            client_id = "paqqladucu"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_default_3(mode): # Test 5
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "iftsntwcyl"
        else:
            client_id = "gbypcbxtum"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&nonce=500&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_dbc(mode): # Test 8
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "dxmdhauyrr"
        else:
            client_id = "lzuwcmivmg"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_gaiax(mode): # Test 9
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "xpkhvsemfd"
        else:
            client_id = "iddznwujyy"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    
def verifier_gaiax_2(mode): # Test 10
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "zkzkwshdns"
        else:
            client_id = "ejqwxtjdlu"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    
def verifier_gaiax_3(mode): # Test 11
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "feyfeamejt"
        else:
            client_id = "ypsfdlfoti"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)

def verifier_ebsiv3(mode): # Test 12
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "novanyhlhs"
        else:
            client_id = "uxcdccjhmq"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)
    

def verifier_ebsiv3_2(mode): # Test 13
    if request.method == 'GET':
        if mode.myenv == 'aws':
            client_id = "rkubsscrkt"
        else:
            client_id = "zvuzyxjhjk"
        url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect(url)


def verifier_callback():
    return jsonify(request.args)