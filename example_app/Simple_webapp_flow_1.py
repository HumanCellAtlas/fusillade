from furl import furl
from requests_oauthlib import OAuth2Session
from flask import Flask, request, redirect, session, url_for
import os

app = Flask(__name__)

domain = "https://auth.dev.data.humancellatlas.org"  #  Change to your domain
authorization_base_url = f'{domain}/authorize'
token_url = f'{domain}/oauth/token'
scopes = 'openid email profile'
userinfo_url = f"{domain}/userinfo"

@app.route("/")
def demo():
    """Step 1: User Authorization.

    Redirect the user/resource owner to the OAuth provider (i.e. Github)
    using an URL with a few key OAuth parameters.
    """
    fusillade = OAuth2Session(scope=scopes, redirect_uri=REDIRECT_URI)
    authorization_url, state = fusillade.authorization_url(authorization_base_url)

    # State is used to prevent CSRF, keep this for later.
    session['oauth_state'] = state
    return redirect(authorization_url)

# Step 2: User authorization, this happens on the provider.

@app.route("/callback", methods=["GET"])
def callback():
    """ Step 3: Store access token."""
    token = dict(furl(request.url).args)
    session['oauth_token'] = token
    return redirect(url_for('.profile'))


@app.route("/profile", methods=["GET"])
def profile():
    """TODO Fetching a protected resource using an OAuth 2 token.
    """
    fusillade = OAuth2Session(token=session['oauth_token'])
    resp = fusillade.get(userinfo_url)
    return resp


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(24)
    port = 5000
    REDIRECT_URI = f"http://127.0.0.1:{port}/callback"
    app.run(debug=True, port=port)
