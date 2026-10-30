"""Keep mobile association files and app links independent of the home redirect."""
import ast
import json
import logging
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request

ROOT = Path(__file__).resolve().parents[1]


def test_home_redirect_preserves_mobile_links(monkeypatch):
    monkeypatch.chdir(ROOT)
    app = Flask('app-links-check', template_folder=str(ROOT / 'templates'))
    env = dict(app=app, request=request, jsonify=jsonify, redirect=redirect,
               render_template=render_template, json=json, logging=logging)
    names = {'assetlinks', 'apple_app_site_association', 'app_callback'}
    tree = ast.parse((ROOT / 'main.py').read_text())
    handlers = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in handlers} == names
    exec(compile(ast.Module(body=handlers, type_ignores=[]), 'main.py', 'exec'), env)
    tree = ast.parse((ROOT / 'routes/saas4ssi.py').read_text())
    home = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'saas_home')
    exec(compile(ast.Module(body=[home], type_ignores=[]), 'routes/saas4ssi.py', 'exec'), env)
    app.add_url_rule('/', view_func=env['saas_home'], methods=['GET', 'POST'])
    client = app.test_client()
    for method in ('get', 'post'):
        response = getattr(client, method)('/')
        assert response.status_code == 302
        assert response.headers['Location'] == 'https://sandbox.openid4vc-hub.com/'
    for path, filename in (
        ('/.well-known/assetlinks.json', 'assetlinks.json'),
        ('/.well-known/apple-app-site-association', 'apple-app-site-association'),
    ):
        response = client.get(path)
        assert response.status_code == 200
        assert response.mimetype == 'application/json'
        assert 'Location' not in response.headers
        assert response.json == json.loads((ROOT / filename).read_text())
    for path in ('/app/download/oidc4vc', '/app/download/authorize', '/app/download/callback'):
        response = client.get(path + '?request_uri=https%3A%2F%2Fexample.org%2Frequest')
        assert response.status_code == 200
        assert 'Location' not in response.headers
