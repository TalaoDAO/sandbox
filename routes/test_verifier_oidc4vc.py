from flask import Flask, jsonify, render_template_string, redirect, request
import flask
from flask_session import Session
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
import redis


def init_app(app,red, mode) :
    app.add_url_rule('/sandbox/verifier/default',  view_func=verifier_default, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/ebsiv2',  view_func=verifier_ebsiv2, methods = ['GET'], defaults={'mode' : mode})
    app.add_url_rule('/sandbox/verifier/ebsiv2_2',  view_func=verifier_ebsiv2_2, methods = ['GET'], defaults={'mode' : mode})


    app.add_url_rule('/sandbox/verifier/callback',  view_func=verifier_callback, methods = ['GET'])
   


def verifier_default(mode):
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = ""
        else :
            client_id = "ybbiskyifx"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)
    

def verifier_ebsiv2(mode):
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "oahrmewate"
        else :
            client_id = "pixsovsisy"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)


def verifier_ebsiv2_2(mode):
    if request.method == 'GET' :
        if mode.myenv == 'aws':
            client_id = "okiwojrycf"
        else :
            client_id = "cinuwjuhvj"
        url = mode.server + "sandbox/ebsi/authorize?client_id=" + client_id +"&scope=openid&response_type=id_token&response_mode=query&redirect_uri=" + mode.server + "sandbox/verifier/callback"
        return redirect (url)



def verifier_callback() :
    return jsonify(request.args)