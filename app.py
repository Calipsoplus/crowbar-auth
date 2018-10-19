import flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import flask_saml
import os
import json
from functools import wraps
from cryptography.fernet import Fernet, InvalidToken
import logging

logging.basicConfig(filename='crowbar-auth.log', level=logging.DEBUG)
os.environ["http_proxy"] = ""
os.environ["https_proxy"] = ""

app = flask.Flask(__name__)

app.config.from_pyfile('config.cfg')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['CORS_HEADERS'] = 'Content-Type'

CORS(app)
saml = flask_saml.FlaskSAML(app)

db = SQLAlchemy(app)
ma = Marshmallow(app)

from VirtualMachine import *

fernet = Fernet(app.config['FERNET_KEY'])


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_token = None
        user_token = None

        # Need to get user cookie

        if flask.request.cookies.get(app.config['COOKIE_AUTH']):
            auth_token = flask.request.cookies.get(app.config['COOKIE_AUTH'])

        if flask.request.cookies.get(app.config['COOKIE_USER']):
            user_token = flask.request.cookies.get(app.config['COOKIE_USER'])

        if not auth_token or not user_token:
            return flask.jsonify({'message': 'Token is missing'}), 401

        try:
            fernet.decrypt(bytes(auth_token, 'utf-8'))
            fernet.decrypt(bytes(user_token, 'utf-8'))
        except InvalidToken:
            logging.warning('Invalid token. Authentication failed')
            return flask.redirect(flask.url_for('login'))
        except Exception as e:
            print(e)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/')
def index():
    resp = flask.make_response(flask.redirect(app.config['CROWBAR_WEB_IP']))

    # Set cookies with encrypted data and time limit of 30 minutes
    resp.set_cookie(app.config['COOKIE_USER'], fernet.encrypt(json.dumps(flask.session['user']).encode('utf-8')), max_age=60 * 30)
    resp.set_cookie(app.config['COOKIE_AUTH'], fernet.encrypt(json.dumps(flask.session['auth']).encode('utf-8')), max_age=60 * 30)

    return resp


@app.route('/machines', methods=['GET'])
@login_required
def get_all_machines():
    all_machines = VirtualMachine.query.all()
    vm_schema = VirtualMachineSchema(many=True)
    result = vm_schema.dump(all_machines)
    response = flask.jsonify(result.data)
    response.headers.add('Access-Control-Allow-Origin', app.config['CROWBAR_WEB_IP'])
    response.headers.add('Access-Control-Allow-Methods', 'GET')
    return response


@app.route('/virtualmachines/user', methods=['GET'])
# @login_required
def get_user_machines():
    result = []
    response = flask.jsonify(result)

    try:
        user = (fernet.decrypt(bytes(flask.request.cookies.get(app.config['COOKIE_USER']), 'utf-8'))).decode("utf-8")
        user = user.replace('"', '')
        user_machines = VirtualMachine.query.filter_by(owner=user).all()
        vm_schema = VirtualMachineSchema(many=True)
        result = vm_schema.dump(user_machines)
        response = flask.jsonify(result.data)
    except InvalidToken:
        logging.warning('Invalid user. Authentication failed')
        return flask.redirect(flask.url_for('login'))

    response.headers.add('Access-Control-Allow-Origin', app.config['CROWBAR_WEB_IP'])
    response.headers.add('Access-Control-Allow-Methods', 'GET')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

@app.route('/userdetails')
def get_user_details():
    data = {app.config['COOKIE_USER']: flask.request.cookies.get(app.config['COOKIE_USER']),
            app.config['COOKIE_AUTH']: flask.request.cookies.get(app.config['COOKIE_AUTH'])}

    if app.config['COOKIE_USER'] in flask.request.cookies:
        response = flask.jsonify(data)
    else:
        response = flask.jsonify('')
    response.headers.add('Access-Control-Allow-Origin', app.config['CROWBAR_WEB_IP'])
    response.headers.add('Access-Control-Allow-Methods', 'GET')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response


@app.route('/token')
def get_token():
    # return flask.redirect(flask.url_for('login')) :Todo revert to this after initial demo

    resp = flask.make_response(flask.redirect(app.config['CROWBAR_WEB_IP']))

    # Set cookies with encrypted data and time limit of 30 minutes
    resp.set_cookie(app.config['COOKIE_USER'], fernet.encrypt(json.dumps('calipso').encode('utf-8')), max_age=60 * 30)
    resp.set_cookie(app.config['COOKIE_AUTH'], fernet.encrypt(json.dumps('calipsoplus-jra2').encode('utf-8')), max_age=60 * 30)

    return resp

@flask_saml.saml_authenticated.connect_via(app)
def on_saml_authenticated(sender, subject, attributes, auth):

    attributes_json = json.JSONEncoder().encode(attributes)
    attributes_list = json.loads(attributes_json)

    flask.session['auth'] = subject
    flask.session['user'] = ''.join(attributes_list['uid'])


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
