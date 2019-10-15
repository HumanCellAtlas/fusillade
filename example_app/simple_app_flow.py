"""
This flask application demonstrates a simple application flow, silent authentication, and logout using fusillade.
This can be used to build single page applications or web applications that require authentication with fusillade.


Silent authentication:
1. Login: visit localhost:{port} to login and retrieve an access token.
2. Check Session: visit localhost:{port}/checksession to retrieve a new access token.
3. Logout: visit localhost:{port}/logout to end the sessions
4. Check Session: visit localhost:{port}/checksession to verify the sessions is close and that a new access token is no
   retrieved.

"""
import os

import requests
from flask import Flask, request, redirect, session, json
from flask.json import jsonify
from furl import furl
from requests_oauthlib import OAuth2Session

app = Flask(__name__)

port=5001
domain = "https://auth.dev.data.humancellatlas.org/"  # Point at your desired domain
authorization_base_url = f'{domain}/oauth/authorize'
logout_base_url = f'{domain}/logout'
scopes = 'openid email profile'


@app.route("/")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    github = OAuth2Session(scope=scopes)
    authorization_url, state = github.authorization_url(authorization_base_url)
    authorization_url = furl(authorization_url).add(query_params=dict(redirect_uri=f"{request.host_url}callback",
                                                                      scopes=scopes))
    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)


# Step 2: User authorization, this happens on the provider.
@app.route("/callback", methods=["GET"])
def callback():
    # At this point you can fetch protected resources but lets save
    # the token and show how this is done from a persisted token
    # in /profile.
    assert session['oauth_state'] == request.args['state']
    session['access_token'] = request.args['access_token']
    session['username'] = json.loads(request.args['decoded_token'])['email']
    return jsonify(200)


@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    url = furl(f"{domain}/v1/user/{session['username']}").url
    resp = requests.get(url, headers=get_auth_header()).json()
    resp['access_token'] = session['access_token']
    return jsonify(resp)


@app.route("/logout", methods=["GET"])
def logout():
    """
    The user is logged out of fusillade
    :return:
    """
    # TODO add logout api to fusillade
    session.clear()
    url = furl(logout_base_url, query_params=dict(
        returnTo='pass'
    )).url
    return redirect(url)


@app.route("/checksession", methods=["GET"])
def checksession():
    """
    A new access token is retrieved while the user is logged in.
    https://auth0.com/docs/api-auth/tutorials/silent-authentication
    :return:
    """
    github = OAuth2Session(scope=scopes)
    authorization_url, state = github.authorization_url(authorization_base_url)
    authorization_url = furl(authorization_url).add(query_params=dict(redirect_uri=f"{request.host_url}callback",
                                                                      scopes=scopes,
                                                                      prompt="none"))
    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)


def get_auth_header(token=None):
    if not token:
        token = session['access_token']
    return {"Authorization": f"Bearer {token}"}


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"
    app.secret_key = os.urandom(24)
    app.run(debug=True, port=port)
