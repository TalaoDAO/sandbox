import os
import time
import markdown
from flask import Flask, redirect, request, render_template_string, request, jsonify
from flask_session import Session
from flask_mobility import Mobility
import requests
from flask_restx import Resource, Api, fields, reqparse
import uuid
from datetime import timedelta
from flask_qrcode import QRcode
import redis
import sys
import json
import logging
import environment
from components import message
logging.basicConfig(level=logging.INFO)

# Environment variables set in gunicornconf.py  and transfered to environment.py
mychain = os.getenv('MYCHAIN')
myenv = os.getenv('MYENV')
if not myenv :
   myenv='local'
logging.info('start to init environment')
mode = environment.currentMode(mychain,myenv)
logging.info('end of init environment')

# Redis init red = redis.StrictRedis()
red= redis.Redis(host='localhost', port=6379, db=0)

# Basic protocole
from routes import verifier_console, issuer_console, api_verifier, api_issuer
from routes import saas4ssi

# OIDC4VC
from routes import oidc4vp_api, oidc4vp_console
from routes import oidc4vci_api, oidc4vci_console

# for testing purpose
from routes import test_issuer_oidc4vc
from routes import test_verifier_oidc4vc
from routes import  web_wallet_test
from routes import web_display_VP

# Framework Flask and Session setup
app = Flask(__name__)
app.jinja_env.globals['Version'] = "0.3.0"
app.jinja_env.globals['Created'] = time.ctime(os.path.getctime('main.py'))
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "OCML3BRawWEUeaxcuKHLpw" + mode.password
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["jpeg", "jpg", "png", "gif"]


sess = Session()
sess.init_app(app)
qrcode = QRcode(app)
Mobility(app)

@app.errorhandler(403)
def page_abort(e):
    logging.warning('abort 403')
    return redirect(mode.server + 'login/')


@app.errorhandler(500)
def error_500(e):
    message.message("Error 500 on sandbox", 'thierry.thevenet@talao.io', str(e) , mode)
    return redirect(mode.server + '/sandbox')


# BASIC wallet protocol
api_verifier.init_app(app, red, mode)
api_issuer.init_app(app, red, mode)
verifier_console.init_app(app, red, mode)
issuer_console.init_app(app, red, mode)

# OIDC4VC wallet
oidc4vp_console.init_app(app, red, mode)
oidc4vp_api.init_app(app, red, mode)
oidc4vci_console.init_app(app, red, mode)
oidc4vci_api.init_app(app, red, mode)

# MAIN
saas4ssi.init_app(app, red, mode)

# TEST
web_display_VP.init_app(app, red, mode)
web_wallet_test.init_app(app, red, mode)
test_issuer_oidc4vc.init_app(app, red, mode)
test_verifier_oidc4vc.init_app(app, red, mode)


@app.route('/sandbox/md_file', methods = ['GET'])
def md_file() :
	#https://dev.to/mrprofessor/rendering-markdown-from-flask-1l41
    if request.args['file'] == 'privacy' :
        content = open('privacy_en.md', 'r').read()
    elif request.args['file'] == 'terms_and_conditions' :
        content = open('mobile_cgu_en.md', 'r').read()
    return render_template_string( markdown.markdown(content, extensions=["fenced_code"]))


################# GREENCYPHER API

PROJECT_LIST = ['CET','GNT']
credential_file = { "GNT" : "GntProject.jsonld", "CET" : "CetProject.jsonld"}
credential_name = { "GNT" : "GntProject", "CET" : "CetProject"}

CET_example = [
    {
        "projectId": "256",
        "acquiredBy": "MyCompany Ltd.",
        "name": "Amazon Forest #234",
        "numberOfCredits": 350
    },
    {
        "projectId": "123",
        "acquiredBy": "MyCompany Ltd.",
        "name": "Kenyan Forest #234",
        "numberOfCredits": 100
    }
]

GNT_example = [
    {
        "projectId": "256",
        "acquiredBy": "MyCompany Ltd.",
        "name": "Kenyan Electrityty #014",
        "numberOfCredits": 800
    }
]

api = Api()

authorizations = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY'
    }
}

api = Api(app, doc='/sandbox/greencypher/swagger',
        authorizations=authorizations,
        description="API description for the GreenCypher issuer. An apikey is needed to access that API, contact@talao.cio",
        titles="GreenCypher API")
ns = api.namespace('GreenCypher', description='Market place issuer')

user_model = api.model('User', {
        "userId" : fields.String (example=123, required=True),
		"firstName" : fields.String(example="John"),
		"lastName" : fields.String(example="Doe"),
		"accountType" : fields.String(example="Monitor"),
        "workForLegalName" : fields.String(example="MyCompany Ltd."),
        "workForId" : fields.String(example="126"),
        "email" : fields.String(example="john.doe@gamil.com")
})


project_model = api.model("Project",{
                "projectId" : fields.String (required=True),
        		"acquiredBy" : fields.String,
        		"name" : fields.String,
        		"numberOfCredits": fields.Integer    
			},)


project_type_model = api.model('Project type', {
        "CET" : fields.List(fields.Nested(project_model), example=CET_example),
		"GNT" : fields.List(fields.Nested(project_model), example=GNT_example),
        "GNT+" : fields.List(fields.Nested(project_model)),
		"SDGT" : fields.List(fields.Nested(project_model)),
        "HOT" : fields.List(fields.Nested(project_model)),
		"RET" : fields.List(fields.Nested(project_model)),
		"XCT" : fields.List(fields.Nested(project_model)),
})

payload = api.model('Payload input', {
    'state': fields.String (example='765765:98676:9797', required=True),
    'callback': fields.Url('todo_resource', required=True, absolute=True, scheme='https', example="https://my.marketplace.com/callback"),
    'user': fields.Nested(user_model),
    'projects' : fields.Nested(project_type_model)
})

response = api.model('Response', {
    'redirect_uri': fields.String(description='API response', required=True),
})

@ns.route('/sandbox/greencypher/acx/issuer', endpoint='acx_issuer')
class Issuer(Resource):
       
    @api.response(200, 'Success')
    @api.doc(responses={404: 'Not Authorized'})
    @api.doc(responses={400: 'Bad Request'})
    @api.doc(security='apikey')
    @api.expect(payload)
    @api.doc(model=response)

    def post(self):  
        apikey = request.headers.get('X-API_KEY')  
        user =  request.json.get('user')
        projects =  request.json.get('projects')
        state =  request.json.get('state')
        callback = request.json.get('callback')
        if not state :
            return {'message' : 'state is missing'}, 400
        if not callback :
            return {'message' : 'callback is missing'}, 400
        if apikey != "greencypher" :
             return {"message" : 'Not Authorized'  }, 404
        if not user and not projects :
            return {'message' : 'user and projects missing'}, 400
        
        data = {
            "issuer_state" : state,
            "pre-authorized_code" : True,
            "credential_type" : list(), 
            "callback" : callback,
            "vc" : list()
        }

        if user :
            data['credential_type'].append('GreencypherPass')
            data['vc'].append(
                {
                    "type" : "GreencyphaerPass",
                    "types" : ["VerifiableCredentials", "GreencypherPass"],
                    "list" : [
                        {
                            "identifier" : "greecypherpass_01",
                            "value" : build_credential_greencypherpass(user)
                        }
                    ]
                }
            )
        if projects :
            for project_type in PROJECT_LIST :
                if projects.get(project_type) :
                    data['credential_type'].append(credential_name[project_type])
                    project_list = list()
                    for project in projects[project_type] :
                        project_list.append(
                            {
                                "identifier" : project['projectId'],
                                "value" : build_credential_projects(credential_file[project_type], project)
                            }
                        )
                    data['vc'].append(
                        {
                            "type" : credential_name[project_type],
                            "types" : ["VerifiableCredentials", credential_name[project_type]],
                            "list" : project_list
                        }
                    )    
                   

        print('data = ', data)
        if mode.myenv == 'aws' :
            api_endpoint = "https://talao.co/sandbox/ebsi/issuer/api/nkpbjplfbi"
            client_secret = "ed055e57-3113-11ee-a280-0a1628958560"
        else :
            api_endpoint = mode.server + "sandbox/ebsi/issuer/api/uxzjfrjptk"
            client_secret = "2675ebcf-2fc1-11ee-825b-9db9eb02bfb8"
        headers = {
            'Content-Type': 'application/json',
            'Authorization' : 'Bearer ' + client_secret
        }
        resp = requests.post(api_endpoint, headers=headers, json = data)
        #return {"test" : "ok"}
        return resp.json()



def build_credential_greencypherpass(user) :
    credential = json.load(open('verifiable_credentials/GreencypherPass.jsonld', 'r'))
    credential['credentialSubject']['firstName'] = user['firstName']
    credential['credentialSubject']['lastName'] = user['lastName']
    credential['credentialSubject']['accounrType'] = user['accountType']
    credential['credentialSubject']['userId'] = user['userId']
    credential['credentialSubject']['workForId'] = user['workForId']
    credential['credentialSubject']['email'] = user['email']
    return credential


def build_credential_projects(credential_file, project_data) :
    credential = json.load(open('verifiable_credentials/' + credential_file, 'r'))
    credential['credentialSubject']['projectId'] = project_data['projectId']
    credential['credentialSubject']['acquiredBy'] = project_data['acquiredBy']
    credential['credentialSubject']['name'] = project_data['name']
    credential['credentialSubject']['numberOfCredits'] = project_data['numberOfCredits']
    return credential


# MAIN entry point for test
if __name__ == '__main__':
    # info release
    logging.info('flask test serveur run with debug mode')
    app.run(host = mode.flaskserver,
            port= mode.port,
            debug = mode.test,
            threaded=True)
    


  