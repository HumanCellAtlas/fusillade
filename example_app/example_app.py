import os
from typing import List, Optional, Dict, Any

import requests
from flask import Flask, request, redirect, session, url_for, json, make_response
from flask.json import jsonify
from furl import furl
from requests_oauthlib import OAuth2Session

"""
I am an API an i would like to strict who has access to what endpoints

Actions:
    SP:GetData
    SP:WriteData

Resources
    /data/{slot}


SAMPLE-READER:
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "SAMPLE-READER",
          "Effect": "Allow",
          "Action": [
            "SP:GetData"
          ],
           "Resource": "arn:project:service:*:*:data/1/collection/dss"
        }
      ]
    }

SAMPLE-RW:
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SAMPLE-RW",
      "Effect": "Allow",
      "Action": [
        "SP:GetData",
        "SP:WriteData"
      ],
       "Resource": "arn:project:service:*:*:data/*"
    }
  ]
}

# fusillade admin
#  create admin account
    POST /v1/user/
    { 
        'user_id': "new_admins_email",
        'roles': ['fusillade_admin', 'sample_admin']
    }

#  login
#  add new roles
    POST /v1/role/
    {   
        'role_id': 'SAMPLE-RW',
        'policy': {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Sid": "SAMPLE-RW",
                          "Effect": "Allow",
                          "Action": [
                            "SP:GetData",
                            "SP:WriteData"
                          ],
                           "Resource": "arn:project:service:*:*:data/*"
                        }
                      ]
                    }
    }

    POST /v1/role/
    {   
        'role_id': 'SAMPLE-READER',
        'policy': {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Sid": "SAMPLE-READER",
                          "Effect": "Allow",
                          "Action": [
                            "SP:GetData"
                          ],
                           "Resource": "arn:project:service:*:*:data/*"
                        }
                      ]
                    }
    }

   GET /v1/role/SAMPLE_READER


#  add default SP policy [WIP]
    PUT /v1/user/default_roles?action=add
    {"roles": ["SAMPLE-READER"]}

# login user
#  user tries to write data to data/1
    POST /v1/evaluate
    {
        principle: 'user's email',
        action: 'SP:WriteData',
        resource: 'arn:hca:sp:*:*:data/1'
    }
#  the user did not exist before so the default policy is assigned to the user and they are denied access
#  user tried to read data, the default policy allows reading so the user is able to read date
    POST /v1/evaluate
    {
        principle: 'user's email',
        action: 'SP:GetData',
        resource: 'arn:hca:sp:*:*:data/1
    }

# admin can assigned the user write permissions
    PUT /v1/user/user_email?action=add
    {"roles": ["SAMPLE-RW"]}

# the user tries to write again and is allowed to write.
    POST /v1/evaluate
    {
        principle: 'user's email',
        action: 'SP:WriteData',
        resource: 'arn:hca:sp:*:*:data/1
    }



# in the future resource can be used to map to a object in cloud directory with policies attached.
"""

app = Flask(__name__)

domain = "http://localhost:5000"  # Point at your desired domain
authorization_base_url = f'{domain}/oauth/authorize'
scopes = 'openid email profile'

slots = [0 for i in range(16)]


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


@app.route("/profile", methods=["GET"])
def profile():
    """Fetching a protected resource using an OAuth 2 token.
    """
    url = furl(f"{domain}/v1/user/{session['username']}").url
    return jsonify(requests.get(url, headers=get_auth_header()).json())


@app.route("/data/<slot>", methods=["GET"])
def get_data(slot):
    slot = int(slot)
    headers = {'Content-Type': "application/json"}
    headers.update(get_auth_header())
    result = requests.post(
        f"{domain}/v1/policies/evaluate",
        headers=headers,
        data=json.dumps({
            "action": ["SP:GetData"],
            "resource": [f"arn:hca:SP:*:*:data/{slot}"],
            "principal": session['username']
        })).json()['result']
    if result:
        return jsonify(slot=slots[slot])
    else:
        return make_response("Unauthorize", 403)


@app.route("/data/<slot>", methods=["PUT"])
def put_data(slot):
    slot = int(slot)
    result = requests.post(
        f"{domain}/v1/policies/evaluate",
        headers=get_auth_header(),
        data=json.dumps({
            "action": ["SP:PutData"],
            "resource": [f"arn:hca:SP:*:*:data/{slot}"],
            "principal": session['username']
        })).json()['result']
    if result:
        slots[slot] = request.data
        return make_response(f"slot {slot} modified", 200)
    else:
        return make_response("Unauthorize", 403)


if __name__ == "__main__":
    # This allows us to use a plain HTTP callback
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = "1"

    app.secret_key = os.urandom(24)
    app.run(debug=True, port=5001)
