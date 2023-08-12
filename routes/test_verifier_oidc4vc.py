from flask import jsonify,  redirect, request


def init_app(app,red, mode) :
    app.add_url_rule('/sandbox/verifier/default',  view_func=verifier_default, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/default_2',  view_func=verifier_default_2, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/default_3',  view_func=verifier_default_3, methods = ['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/verifier/ebsiv2',  view_func=verifier_ebsiv2, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/ebsiv2_2',  view_func=verifier_ebsiv2_2, methods = ['GET'], defaults={'mode' : mode})


    app.add_url_rule('/sandbox/verifier/hedera',  view_func=verifier_hedera, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/hedera_2',  view_func=verifier_hedera_2, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/hedera_3',  view_func=verifier_hedera_3, methods = ['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/verifier/gaiax',  view_func=verifier_hedera, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/gaiax_2',  view_func=verifier_hedera_2, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/gaiax_3',  view_func=verifier_hedera_3, methods = ['GET'], defaults={'mode' : mode})

    app.add_url_rule('/sandbox/verifier/callback',  view_func=verifier_callback, methods = ['GET'])
   


def verifier_default(mode): # Test 3
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "rxbypnwhxc"
        else :
            client_id = "ybbiskyifx"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&nonce=100&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)


def verifier_default_2(mode): # Test 4
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "wvjotpxxrd"
        else :
            client_id = "paqqladucu"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)


def verifier_default_3(mode): # Test 5
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "iftsntwcyl"
        else :
            client_id = "gbypcbxtum"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&nonce=500&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)


def verifier_ebsiv2(mode): # Test 1
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "oahrmewate"
        else :
            client_id = "pixsovsisy"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)


def verifier_ebsiv2_2(mode): # Test 2
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "okiwojrycf"
        else :
            client_id = "cinuwjuhvj"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)

def verifier_hedera(mode): # Test 6
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "yxluhubhor"
        else :
            client_id = "frigcycvbg"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)

def verifier_hedera_2(mode): # Test 7
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "ctetbsbltd"
        else :
            client_id = "vzhawcuror"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)

def verifier_hedera_3(mode): # Test 8
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "dxmdhauyrr"
        else :
            client_id = "lzuwcmivmg"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)


def verifier_gaiax(mode): # Test 9
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "xpkhvsemfd"
        else :
            client_id = ""
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)
    
def verifier_gaiax_2(mode): # Test 10
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "zkzkwshdns"
        else :
            client_id = ""
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)
    
def verifier_gaiax_3(mode): # Test 11
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "feyfeamejt"
        else :
            client_id = "ypsfdlfoti"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)


def verifier_callback() :
    return jsonify(request.args)