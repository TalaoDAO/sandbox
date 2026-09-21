from flask import Flask, render_template_string, request
from flask_qrcode import QRcode
from flask_session import Session
import requests
import redis


# Redis
red = redis.Redis(host="localhost", port=6379, db=0)


# Flask
app = Flask(__name__)

app.config["SESSION_PERMANENT"] = True
app.config["SESSION_COOKIE_NAME"] = "talao"
app.config["SESSION_TYPE"] = "redis"
app.config["SESSION_FILE_THRESHOLD"] = 100

sess = Session()
sess.init_app(app)

qrcode = QRcode(app)


WALTID_BASE_URL = "https://issuer2.demo.walt.id"


def init_app(app, red, mode):
    app.add_url_rule(
        "/sandbox/issuer/waltid/test",
        view_func=waltid,
        methods=["GET", "POST"]
    )
    return


def waltid():

    #
    # GET: display flow selector
    #
    if request.method == "GET":

        html_string = """
        <html>
        <head>
            <title>Walt.id OIDC4VCI Test</title>
        </head>

        <body>

            <h1>Walt.id OIDC4VCI Test</h1>

            <form method="POST">

                <label for="flow">
                    Select OIDC4VCI flow:
                </label>

                <select name="flow" id="flow">

                    <option value="pre_authorized">
                        Pre-Authorized Code Flow
                    </option>

                    <option value="authorization_code">
                        Authorization Code Flow
                    </option>

                </select>

                <br><br>

                <button type="submit">
                    Create Credential Offer
                </button>

            </form>

        </body>
        </html>
        """

        return render_template_string(html_string)

    #
    # POST: create credential offer
    #

    flow = request.form.get("flow")

    if flow == "pre_authorized":

        payload = {
            "profileId": "identityCredentialSdJwt",
            "authMethod": "PRE_AUTHORIZED",
            "txCode": {
                "input_mode": "numeric",
                "length": 6,
                "description": "Enter the PIN shown by the issuer"
            },
            "txCodeValue": "123456"
        }

        flow_name = "Pre-Authorized Code Flow"

    elif flow == "authorization_code":

        payload = {
            "profileId": "identityCredentialSdJwt",
            "authMethod": "AUTHORIZED",
            "issuerStateMode": "INCLUDE"
        }

        flow_name = "Authorization Code Flow"

    else:

        return "Invalid OIDC4VCI flow", 400

    #
    # Call Walt.id Issuer2
    #

    url = f"{WALTID_BASE_URL}/issuer2/credential-offers"

    try:

        resp = requests.post(
            url,
            headers={
                "Content-Type": "application/json"
            },
            json=payload,
            timeout=10
        )

    except requests.RequestException as e:

        return f"Walt.id connection error: {e}", 500

    if resp.status_code >= 400:

        return (
            f"Walt.id error ({resp.status_code}): "
            f"{resp.text}",
            resp.status_code
        )

    try:
        response_json = resp.json()

    except ValueError:

        return "Invalid response from Walt.id", 500

    code = response_json.get("credentialOffer")

    if not code:

        return "No credentialOffer returned by Walt.id", 500

    #
    # Display QR code
    #

    html_string = """
    <html>

    <head>
        <title>Walt.id OIDC4VCI Test</title>
    </head>

    <body>

        <h1>{{ flow_name }}</h1>

        {% if flow == "pre_authorized" %}

            <h2>TX Code: 123456</h2>

        {% endif %}

        <p>{{ code }}</p>

        <div>
            <img src="{{ qrcode(code) }}">
        </div>

        <br><br>

        <a href="/sandbox/issuer/waltid/test">
            Create another offer
        </a>

    </body>

    </html>
    """

    return render_template_string(
        html_string,
        code=code,
        flow=flow,
        flow_name=flow_name
    )