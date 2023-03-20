import os
import json
import base64
import hashlib
import requests
import secrets

from flask import Flask, render_template, redirect, request, session, url_for
from flask_cors import CORS
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from shapely import contains
from shapely.geometry import shape

# multitenant - organized by "sub" subject claim in JWT

app = Flask(__name__)
app.config.update({'SECRET_KEY': secrets.token_hex(64)})
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)

# example of "policy"
aoa = shape({
     "type": "Polygon",
     "coordinates": [
          [
            [
              -122.66772702135009,
              38.02318203831916
            ],
            [
              -122.66772702135009,
              37.198730252116945
            ],
            [
              -121.68060795872898,
              37.198730252116945
            ],
            [
              -121.68060795872898,
              38.02318203831916
            ],
            [
              -122.66772702135009,
              38.02318203831916
            ]
          ]
        ]
        })

aoas = {"97bb21cf-b846-44a1-bb11-eee7f812b3b1": aoa}

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login")
def login():
    # store app state and code verifier in session
    session['app_state'] = secrets.token_urlsafe(64)
    session['code_verifier'] = secrets.token_urlsafe(64)

    # calculate code challenge
    hashed = hashlib.sha256(session['code_verifier'].encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode('ascii').strip('=')

    # get request params
    query_params = {'client_id': config["client_id"],
                    'redirect_uri': config["redirect_uri"],
                    'scope': "openid email profile offline_access",
                    'state': session['app_state'],
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                    'response_type': 'code',
                    'response_mode': 'query'}

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=requests.compat.urlencode(query_params)
    )

    #call the authorize uri to get an authorization code, which on success calls the callback
    return redirect(request_uri)

import asyncio
from okta_jwt_verifier import JWTVerifier, BaseJWTVerifier

async def validateAsync(token):
    verifier = JWTVerifier(config["issuer"], config["client_id"], "api://custom")
    await verifier.verify_access_token(token)

#proxy for authorizing an action based on current policy
def is_aoi_valid(aoa_id, aoi):
    if aoas[aoa_id].contains(shape(json.loads(aoi))):
         return "yes"
    else:
         return "no"

# if unvalidated/unverified, try to refresh
@app.route("/validate", methods=["GET"])
def validate():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(validateAsync(request.args.get("token")))
    return "validated"

#ala PV
@app.route("/validate-aoi", methods=["POST"])
def validate_aoi():
    return is_aoi_valid(current_user.aoa_id, request.form["aoi"])

# this can and should be inside of each PDP method if a token is unverified (JWTValidationException)
@app.route("/refresh-token")
def refresh():
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json', 'cache-control': 'no-cache'}
    query_params = {
       "grant_type": "refresh_token",
       "scope": "openid offline_access profile",
       "refresh_token": config["refresh_token"],
       "redirect_uri": "http://localhost:5000"
    }
    print(query_params)
    query_params = requests.compat.urlencode(query_params)
    response = requests.post(
         config["token_uri"],
         headers=headers,
         data = query_params,
         auth= (config["client_id"], config["client_secret"])
    )
    token = response.json()["access_token"]
    return token

@app.route("/get-token-api")
def get_token_api():
    # store app state and code verifier in session
    session['app_state'] = secrets.token_urlsafe(64)
    session['code_verifier'] = secrets.token_urlsafe(64)

    # calculate code challenge
    hashed = hashlib.sha256(session['code_verifier'].encode('ascii')).digest()
    encoded = base64.urlsafe_b64encode(hashed)
    code_challenge = encoded.decode('ascii').strip('=')

    # get request params
    # client id of native app, this app is acting as native app (mobile app attempting to communicate to API)
    query_params = {'client_id': os.environ["OKTA_NATIVE_APP_CLIENT_ID"],
                    'redirect_uri': "http://localhost:5000/authorization-code/callback-api",
                    'scope': "openid",
                    'state': session['app_state'],
                    'code_challenge': code_challenge,
                    'code_challenge_method': 'S256',
                    'response_type': 'code',
                    'response_mode': 'query'}

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=config["auth_uri"],
        query_params=requests.compat.urlencode(query_params)
    )
    return redirect(request_uri)

@app.route("/authorization-code/callback-api")
def callback_api():
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    # get the code from the successful /authorize request
    code = request.args.get("code")
    app_state = request.args.get("state")
    if app_state != session['app_state']:
        return "The app state does not match"
    if not code:
            return "The code was not returned or is not accessible", 403

    # use returned code and auth for native app to get access token
    query_params = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': request.base_url,
                    'code_verifier': session['code_verifier'],
                    'client_id': os.environ["OKTA_NATIVE_APP_CLIENT_ID"]
                    }
    query_params = requests.compat.urlencode(query_params)

    exchange = requests.post(
        config["token_uri"],
        headers=headers,
        data=query_params,
    ).json()

    token = exchange["access_token"]

    query_params = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token": token,
        "scope": "api:access:read api:access:write",
        "audience": "api://custom"
    }

    # use auth for service app to get access token via exchange
    # this token can be used by an api to talk to another api
    response = requests.post(
        config["token_uri"],
        headers=headers,
        data=query_params,
        auth=(os.environ["OKTA_SERVICE_APP_CLIENT_ID"], os.environ["OKTA_SERVICE_APP_SECRET"])
    )
    return response.json()


# the callback used with an authorization code from /authorize
@app.route("/authorization-code/callback")
def callback():
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    # get the code from the successful /authorize request
    code = request.args.get("code")
    app_state = request.args.get("state")
    if app_state != session['app_state']:
        return "The app state does not match"
    if not code:
            return "The code was not returned or is not accessible", 403
    query_params = {'grant_type': 'authorization_code',
                    'code': code,
                    'redirect_uri': request.base_url,
                    'code_verifier': session['code_verifier'],
                    }
    query_params = requests.compat.urlencode(query_params)

    # get the token using the code
    exchange = requests.post(
        config["token_uri"],
        headers=headers,
        data=query_params,
        auth=(config["client_id"], config["client_secret"])
    ).json()

    # we get a refresh token also, save that - it's useful later
    config["refresh_token"]= exchange["refresh_token"]

    # Get tokens and validate
    if not exchange.get("token_type"):
            return "Unsupported token type. Should be 'Bearer'.", 403
    access_token = exchange["access_token"]
    id_token = exchange["id_token"]

    # Authorization flow successful, get userinfo and login user
    # userinfo should contain all profile attributes if access_token came from `authorize`
    userinfo_response = requests.get(config["userinfo_uri"],
                                    headers={'Authorization': f'Bearer {access_token}'}).json()
    unique_id = userinfo_response["sub"]
    user_email = userinfo_response["email"]
    user_name = userinfo_response["given_name"]

    verifier = BaseJWTVerifier(config["issuer"], config["client_id"], "api://custom")
    headers, claims, signing_input, signature = verifier.parse_token(access_token)
    print(claims)
    aoa_id = claims["aoa"]

    user = User(
        id_=unique_id, name=user_name, email=user_email, aoa_id=aoa_id
    )

    if not User.get(unique_id):
        User.create(unique_id, user_name, user_email, aoa_id)
    login_user(user)

    return redirect(url_for("profile"))

@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))

@app.route("/profile")
def profile():
    return render_template("profile.html", user=current_user)

from user import User

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


if __name__ == '__main__':
    app.run(host="localhost", port=5000, debug=True)

okta_domain = os.environ["OKTA_DOMAIN"]
client_id = os.environ["CLIENT_ID"]
client_secret = os.environ["CLIENT_SECRET"]

config = {
    "auth_uri": f"{okta_domain}/oauth2/aus8s3ux1hJDN8iKd5d7/v1/authorize",
    "client_id": f"{client_id}",
    "client_secret": f"{client_secret}",
    "redirect_uri": "http://localhost:5000/authorization-code/callback",
    "issuer": f"{okta_domain}/oauth2/aus8s3ux1hJDN8iKd5d7",
    "token_uri": f"{okta_domain}/oauth2/aus8s3ux1hJDN8iKd5d7/v1/token",
    "userinfo_uri": f"{okta_domain}/oauth2/aus8s3ux1hJDN8iKd5d7/v1/userinfo",
    "refresh_token": ""
}