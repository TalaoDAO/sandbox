from flask import jsonify,  redirect, request, render_template, redirect, session
import json
import db_api
import oidc4vc
import base64
import urllib.parse

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
    app.add_url_rule('/sandbox/verifier/callback3',  view_func=verifier_callback3, methods=['GET'], defaults={'red': red})

    
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
    print(url)
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
    authorization_details = "%7B%22type%22%3A%22evm.erc20_transfer%22%2C%22credential_ids%22%3A%5B%22over18%22%5D%2C%22chain_id%22%3A1%2C%22asset%22%3A%7B%22symbol%22%3A%22USDT%22%2C%22address%22%3A%220xdAC17F958D2ee523a2206206994597C13D831ec7%22%2C%22decimals%22%3A6%7D%2C%22amount%22%3A%2295000000%22%2C%22recipient%22%3A%220x03817255659dc455079df516c5271b4046b2065b%22%2C%22rpc%22%3A%7B%22method%22%3A%22eth_sendTransaction%22%2C%22params%22%3A%5B%7B%22to%22%3A%220xdAC17F958D2ee523a2206206994597C13D831ec7%22%2C%22value%22%3A%220x0%22%2C%22data%22%3A%220xa9059cbb00000000000000000000000003817255659dc455079df516c5271b4046b2065b0000000000000000000000000000000000000000000000000000000005a995c0%22%7D%5D%7D%2C%22ui_hints%22%3A%7B%22icon_uri%22%3A%22https%3A//talao.co/server/image/whisky.png%22%2C%22purpose%22%3A%22BuyThe%20Yamazaki%20-%20Distiller%27s%20R%5Cu00e9serve%20%22%7D%2C%22eip681%22%3A%22ethereum%3A0xdAC17F958D2ee523a2206206994597C13D831ec7%401/transfer%3Faddress%3D0x03817255659dc455079df516c5271b4046b2065b%26uint256%3D95000000%22%7D"
    session['verified'] = False
    if mode.myenv == 'aws':
        client_id = "woxvjqkbrb"
    else:
        client_id = "fzqtmovhto"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&authorization_details=" + authorization_details + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
    return redirect(url)


def verifier_test_13(mode):
    authorization_details = '%7B%22type%22%3A%22evm.erc20_transfer%22%2C%22credential_ids%22%3A%5B%22pid_credential%22%5D%2C%22chain_id%22%3A1%2C%22asset%22%3A%7B%22symbol%22%3A%22TALAO%22%2C%22address%22%3A%220x1D4cCC31dAB6EA20f461d329a0562C1c58412515%22%2C%22decimals%22%3A18%7D%2C%22amount%22%3A%225000000000000000000%22%2C%22recipient%22%3A%220x03817255659dc455079df516c5271b4046b2065b%22%2C%22rpc%22%3A%7B%22method%22%3A%22eth_sendTransaction%22%2C%22params%22%3A%5B%7B%22to%22%3A%220x1D4cCC31dAB6EA20f461d329a0562C1c58412515%22%2C%22value%22%3A%220x0%22%2C%22data%22%3A%220xa9059cbb00000000000000000000000003817255659dc455079df516c5271b4046b2065b0000000000000000000000000000000000000000000000004563918244f40000%22%7D%5D%7D%2C%22order_id%22%3A%2216805%22%2C%22ui_hints%22%3A%7B%22title%22%3A%22This%20is%20a%20test%20for%20an%20ERC20%20transfer%22%2C%22subtitle%22%3A%22Cypto%20%20paiement%22%2C%22purpose%22%3A%22Transfer%205%20TALAO%20to%20Pizza%20Shop%22%7D%2C%22eip681%22%3A%22ethereum%3A0x1D4cCC31dAB6EA20f461d329a0562C1c58412515%401/transfer%3Faddress%3D0x03817255659dc455079df516c5271b4046b2065b%26uint256%3D5000000000000000000%22%7D'
    session['verified'] = False
    if mode.myenv == 'aws':
        client_id = "mnpqhqqrlw"
    else:
        client_id = "nyudzjxuhj"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&authorization_details=" + authorization_details + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
    return redirect(url)


def verifier_test_14(mode):
    authorization_details = "%7B%22type%22%3A%22evm.erc20_transfer%22%2C%22credential_ids%22%3A%5B%22pid_credential%22%5D%2C%22chain_id%22%3A1%2C%22asset%22%3A%7B%22symbol%22%3A%22TALAO%22%2C%22address%22%3A%220x1D4cCC31dAB6EA20f461d329a0562C1c58412515%22%2C%22decimals%22%3A18%7D%2C%22amount%22%3A%225000000000000000000%22%2C%22recipient%22%3A%220x03817255659dc455079df516c5271b4046b2065b%22%2C%22rpc%22%3A%7B%22method%22%3A%22eth_sendTransaction%22%2C%22params%22%3A%5B%7B%22to%22%3A%220x1D4cCC31dAB6EA20f461d329a0562C1c58412515%22%2C%22value%22%3A%220x0%22%2C%22data%22%3A%220xa9059cbb00000000000000000000000003817255659dc455079df516c5271b4046b2065b0000000000000000000000000000000000000000000000004563918244f40000%22%7D%5D%7D%2C%22ui_hints%22%3A%7B%22icon_uri%22%3A%22https%3A//talao.co/server/image/pizza.jpeg%22%2C%22purpose%22%3A%22Pay%20to%20Pizza%20Shop%22%7D%2C%22eip681%22%3A%22ethereum%3A0x1D4cCC31dAB6EA20f461d329a0562C1c58412515%401/transfer%3Faddress%3D0x03817255659dc455079df516c5271b4046b2065b%26uint256%3D5000000000000000000%22%7D"
    session['verified'] = False
    if mode.myenv == 'aws':
        client_id = "cfjiehhlkn"
    else:
        client_id = "frrrgvvtdt"
    url = mode.server + "sandbox/verifier/app/authorize?client_id=" + client_id + "&authorization_details=" + authorization_details + "&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback3"
    return redirect(url)


def verifier_callback():
    return jsonify(request.args)


def verifier_callback3(red):
    # Check for error in request
    if request.args.get("error"):
        return jsonify(request.args)
    # Extract tokens
    token = request.args.get("id_token")
    try:
        if token in [None, 'None']:
            token = red.get(request.args.get("vp_token_urn")).decode()
        raw = red.get(request.args.get("raw_urn")).decode()
    except Exception:
        return jsonify({"error": "timeout"})
    
    presentation_submission = request.args.get("presentation_submission")

    # Fallback for wallet-specific token
    if presentation_submission == "null":
        token = request.args.get("wallet_id_token")
        return jsonify({
            "header": oidc4vc.get_header_from_token(token),
            "payload": oidc4vc.get_payload_from_token(token)
        })

    # Step 1: URL-decode the token
    decoded_str = urllib.parse.unquote(token)

    # Step 2: Handle either a single token or a list of tokens
    try:
        data = json.loads(decoded_str)
        vp_tokens = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        vp_tokens = [decoded_str]

    disclosure = ""
    # Initialize final values to fallback in case parsing fails
    vcsd_jwt_header = {}
    vcsd_jwt_payload = {}
    kbjwt_header = "No KB"
    kbjwt_payload = "No KB"

    # Process each vp_token
    vp_token = []
    blockchain_transaction_list = []
    for token in vp_tokens:
        vcsd = token.split("~")

        # Extract vcsd_jwt
        vcsd_jwt = vcsd[0]
        try:
            vcsd_jwt_header = oidc4vc.get_header_from_token(vcsd_jwt)
            vcsd_jwt_payload = oidc4vc.get_payload_from_token(vcsd_jwt)
            print()
        except Exception:
            continue
        # Extract kb-jwt if it exists
        if vcsd[-1]:
            kb_jwt = vcsd[-1]
            kbjwt_header = oidc4vc.get_header_from_token(kb_jwt)
            kbjwt_payload = oidc4vc.get_payload_from_token(kb_jwt)
            len_vcsd = len(vcsd) - 1
        else:
            len_vcsd = len(vcsd)

        # Decode disclosures
        disclosure = ""
        for i in range(1, len_vcsd):
            _disclosure = vcsd[i]
            _disclosure += "=" * ((4 - len(_disclosure) % 4) % 4)  # Fix base64 padding
            try:
                decoded = base64.urlsafe_b64decode(_disclosure.encode()).decode()
                disclosure += "\r\n" + decoded
            except Exception as e:
                disclosure += f"\r\n[Error decoding disclosure: {str(e)}]"
        vp_token.append({
            "vcsd_jwt_header": json.dumps(vcsd_jwt_header, indent=4),
            "vcsd_jwt_payload": json.dumps(vcsd_jwt_payload, indent=4),
            "disclosure": disclosure,
            "kbjwt_header": json.dumps(kbjwt_header, indent=4),
            "kbjwt_payload": json.dumps(kbjwt_payload, indent=4) 
        })
        try:
            blockchain_hashes = kbjwt_payload.get("blockchain_transaction_hash") or kbjwt_payload.get("blockchain_transaction_hashes")
        except Exception:
            blockchain_hashes = None
                        
        if blockchain_hashes:
            if nonce := kbjwt_payload.get("nonce"):
                # get nonce to look for chain_id
                transaction_data = json.loads(red.get(nonce).decode())[0] # the first one considering we use the same chain for all transactions
                chain_id = transaction_data.get("chain_id")
                for transaction in blockchain_hashes: 
                    explorer = "https://etherscan.io/tx/"
                    if chain_id == 1:
                        pass
                    elif chain_id == 11155111:
                        explorer = "https://sepolia.etherscan.io/tx/"
                    elif chain_id == 137:
                        explorer = "https://polygonscan.com/tx/"
                    elif chain_id == 80002:
                        explorer = "https://amoy.polygonscan.com/tx/"
                    else:
                        pass  #TODO
                    blockchain_transaction_list.append(explorer + transaction)
    
    print("Blockchain transaction URL list = ", blockchain_transaction_list)
                
    #blockchain_explorer = "https://etherscan.io/tx/0xf9423fa82fec28dfeed6110d4416d98dc4926cb7d75432ce8c161b1814050658"
    
    return render_template(
        'verifier_oidc/vcsd_jwt_test.html',
        raw=raw,
        presentation_submission=json.dumps(presentation_submission, indent=4),
        vp_token=vp_token,
        blockchain_transaction_list=blockchain_transaction_list
    )

def verifier_callback2(mode):
    return redirect('/sandbox/verifier/app/logout' + '?post_logout_redirect_uri=' + mode.server + "sandbox/verifier/callback2_1")


def verifier_callback2_1():
    return render_template('face2face.html')