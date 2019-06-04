from requests_oauthlib import OAuth2Session
from furl import furl
import requests
from flask import Flask, request, redirect, session, url_for, json
from flask.json import jsonify
import os

app = Flask(__name__)

# domain = "https://auth.tsmith.data.humancellatlas.org"
domain = "http://localhost:5000"
authorization_base_url = f'{domain}/oauth/authorize'
token_url = f'{domain}/oauth/token'
userinfo_url = f"{domain}/oauth/userinfo"
scopes = 'openid email profile'


def get_auth_header():
    return dict(Authorization=f"Bearer {session['access_token']}")


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
    return redirect(url_for('.profile'))


@app.route("/userinfo", methods=["GET"])
def userinfo():
    """Fetching a protected resource using an OAuth 2 token.
    """
    github = OAuth2Session(token=session['oauth_token'])
    return jsonify(github.get(userinfo_url).json())

@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    url = furl(f"{domain}/v1/user/{session['username']}").url
    return jsonify(requests.get(url, headers=get_auth_header()).json())

if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(24)
    app.run(debug=True, port=5001)