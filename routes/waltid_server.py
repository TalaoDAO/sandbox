from flask import Flask, render_template_string
from flask_qrcode import QRcode
from flask_session import Session
import requests
import redis
import json
import threading


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


payload_preauthorized = {
    "profileId": "identityCredentialSdJwt",
    "authMethod": "PRE_AUTHORIZED",
    "txCode": {
        "input_mode": "numeric",
        "length": 6,
        "description": "Enter the PIN shown by the issuer"
    },
    "txCodeValue": "123456"
}


payload = {
    "profileId": "identityCredentialSdJwt",
    "authMethod": "AUTHORIZED",
    "issuerStateMode": "INCLUDE"
}


#
# Walt.id global SSE event listener
#
def listen_waltid_events():

    url = f"{WALTID_BASE_URL}/issuer2/events"

    print("")
    print("==============================================")
    print("WALT.ID EVENT LISTENER STARTING")
    print("URL:", url)
    print("==============================================")
    print("")

    try:

        with requests.get(
            url,
            stream=True,
            headers={
                "Accept": "text/event-stream"
            },
            timeout=(10, None)
        ) as response:

            print("Walt.id SSE HTTP status:", response.status_code)

            if response.status_code >= 400:
                print("ERROR connecting to Walt.id events:")
                print(response.text)
                return

            print("Connected to Walt.id SSE event stream")
            print("Waiting for events...")
            print("")

            for line in response.iter_lines(decode_unicode=True):

                if not line:
                    continue

                # SSE messages have the format:
                #
                # data: {...}
                #

                if line.startswith("data:"):

                    data = line[5:].strip()

                    if not data:
                        continue

                    try:
                        event = json.loads(data)

                    except json.JSONDecodeError:
                        print("WALT.ID RAW EVENT:")
                        print(data)
                        continue

                    # Ignore initial SSE handshake {}
                    if not event:
                        continue

                    print("")
                    print("==============================================")
                    print("WALT.ID EVENT")
                    print("==============================================")

                    print(json.dumps(
                        event,
                        indent=2,
                        ensure_ascii=False
                    ))

                    event_type = event.get("event")

                    if event_type:
                        print("")
                        print("EVENT TYPE:", event_type)

                    request_id = event.get("requestId")

                    if request_id:
                        print("REQUEST ID:", request_id)

                    target = event.get("target")

                    if target:
                        print("TARGET:", target)

                    #
                    # Explicit error display
                    #
                    error = event.get("error")
                    error_description = event.get(
                        "error_description"
                    )

                    if error or error_description:

                        print("")
                        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                        print("WALT.ID ERROR")
                        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

                        print("ERROR:", error)
                        print(
                            "ERROR DESCRIPTION:",
                            error_description
                        )

                        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

                    print("==============================================")
                    print("")

    except Exception as e:

        print("")
        print("==============================================")
        print("WALT.ID SSE LISTENER ERROR")
        print("==============================================")
        print(type(e).__name__, str(e))
        print("==============================================")
        print("")


#
# Start listener in background
#
event_thread = threading.Thread(
    target=listen_waltid_events,
    daemon=True
)

event_thread.start()


#
# Credential offer
#
def waltid():

    url = f"{WALTID_BASE_URL}/issuer2/credential-offers"

    headers = {
        "Content-Type": "application/json"
    }

    print("")
    print("==============================================")
    print("CREATE WALT.ID CREDENTIAL OFFER")
    print("==============================================")

    print("URL:", url)

    print("Payload:")
    print(json.dumps(
        payload,
        indent=2,
        ensure_ascii=False
    ))

    try:

        resp = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=10
        )

    except Exception as e:

        print("HTTP ERROR:")
        print(type(e).__name__, str(e))

        return str(e), 500

    print("")
    print("HTTP STATUS:", resp.status_code)

    print("")
    print("RESPONSE:")
    print(resp.text)

    if resp.status_code >= 400:

        print("")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("WALT.ID OFFER ERROR")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        print(resp.text)

        return resp.text, resp.status_code

    try:
        response_json = resp.json()

    except Exception:

        print("Response is not JSON")
        return resp.text, 500

    print("")
    print("PARSED RESPONSE:")
    print(json.dumps(
        response_json,
        indent=2,
        ensure_ascii=False
    ))

    code = response_json.get("credentialOffer")

    print("")
    print("==============================================")
    print("QR CODE")
    print("==============================================")
    print(code)
    print("==============================================")

    html_string = """
    <html>

        <head>
            <title>Walt.id OID4VCI Test</title>
        </head>

        <body>

            <h1>Walt.id Authorization Code Flow</h1>

            <h3>{{ code }}</h3>

            <div>
                <img src="{{ qrcode(code) }}">
            </div>

        </body>

    </html>
    """

    return render_template_string(
        html_string,
        code=code
    )