'''
This module contains function to authenticate users using OpenId Connect
https://openid.net/connect/
'''
import base64
import os

import jwt
import requests
import time
from connexion.lifecycle import ConnexionResponse
from flask import json, request, make_response
from furl import furl

from fusillade import Config
from fusillade.errors import FusilladeHTTPException
from fusillade.utils.security import get_openid_config, get_public_key


def login():
    return ConnexionResponse(
        status_code=requests.codes.moved,
        headers=dict(Location='/oauth/authorize'))


def logout():
    oauth2_config = Config.get_oauth2_config()
    openid_provider = Config.get_openid_provider()
    query_params = getattr(Config.app.current_request, 'query_params')
    client_id = oauth2_config[openid_provider]["client_id"] if not query_params else query_params.get('client_id')
    url = furl(f"https://{openid_provider}/v2/logout",
               query_params=dict(client_id=client_id)).url
    return ConnexionResponse(status_code=requests.codes.found,
                             headers={
                                 'Location': url,
                                 'set-cookie': ';'.join(
                                     [f"access_token=",
                                      "SameSite=Strict",
                                      "Domain=humancellatlas.org",
                                      "Secure",
                                      "HttpOnly",
                                      f"Expires={int(time.time()) - Config.cookie_age}",
                                      "path=/"])
                             })


def authorize():
    query_params = request.args.copy() if request.args else {}
    openid_provider = Config.get_openid_provider()
    query_params["openid_provider"] = openid_provider
    query_params['response_type'] = "code"
    client_id = query_params.get("client_id")
    client_id = client_id if client_id != 'None' else None
    if client_id:
        auth_params = query_params
    else:
        state = base64.b64encode(json.dumps(query_params).encode()).decode()
        # TODO: set random state
        oauth2_config = Config.get_oauth2_config()
        auth_params = dict(client_id=oauth2_config[openid_provider]["client_id"],
                           response_type="code",
                           scope="openid email profile",
                           redirect_uri=oauth2_config[openid_provider]["redirect_uri"],
                           state=state,
                           prompt=query_params.get('prompt') if query_params.get('prompt') == 'none' else 'login')

    dest = furl(get_openid_config(openid_provider)["authorization_endpoint"], query_params=auth_params)
    return ConnexionResponse(status_code=requests.codes.found, headers=dict(Location=dest.url))


def proxy_response(dest_url, **extra_query_params):
    cr = Config.app.current_request
    if cr.query_params or extra_query_params:
        dest_url = furl(dest_url).add(dict(cr.query_params, **extra_query_params)).url
    proxy_res = requests.request(method=cr.method,
                                 url=dest_url,
                                 headers=cr.headers,
                                 data=cr.raw_body)
    return make_response(proxy_res.text, proxy_res.status_code, proxy_res.headers.items())


proxied_endpoints = dict(authorization_endpoint=f"https://{os.environ['API_DOMAIN_NAME']}/oauth/authorize",
                         token_endpoint=f"https://{os.environ['API_DOMAIN_NAME']}/oauth/token",
                         jwks_uri=f"https://{os.environ['API_DOMAIN_NAME']}/.well-known/jwks.json",
                         revocation_endpoint=f"https://{os.environ['API_DOMAIN_NAME']}/oauth/revoke",
                         userinfo_endpoint=f"https://{os.environ['API_DOMAIN_NAME']}/oauth/userinfo",
                         logout_endpoint=f"https://{os.environ['API_DOMAIN_NAME']}/logout"
                         )


def serve_openid_config():
    """
    Part of OIDC
    """
    auth_host = request.headers['host']
    if auth_host != os.environ["API_DOMAIN_NAME"]:
        raise FusilladeHTTPException(
            status=400,
            title="Bad Request",
            detail=f"host: {auth_host}, is not supported. host must be {os.environ['API_DOMAIN_NAME']}.")
    openid_config = get_openid_config(Config.get_openid_provider()).copy()
    openid_config.update(**proxied_endpoints)
    return ConnexionResponse(body=openid_config, status_code=requests.codes.ok)


def serve_jwks_json():
    """
    Part of OIDC
    """
    openid_config = get_openid_config(Config.get_openid_provider())
    return proxy_response(openid_config["jwks_uri"])


def serve_oauth_token():
    """
    Part of OIDC
    """
    # TODO: client id/secret mgmt
    openid_provider = Config.get_openid_provider()
    openid_config = get_openid_config(openid_provider)
    return proxy_response(openid_config["token_endpoint"])


def revoke():
    """
    Part of OIDC
    """
    openid_config = get_openid_config(Config.get_openid_provider())
    return proxy_response(openid_config["revocation_endpoint"])


def userinfo(token_info):
    """
    Part of OIDC
    """
    from fusillade.directory import User, Group, Role
    user = User(token_info['email'])
    # TODO save user info in fusillade at the same time.
    token_info[f"https://{os.environ['API_DOMAIN_NAME']}/app_metadata"] = {
        'authorization': {
            'groups': Group.get_names(user.groups),
            'roles': Role.get_names(user.roles),
            'scope': [i for i in user.get_actions()]
        }
    }
    return make_response(json.jsonify(**token_info), requests.codes.ok)


def get_userinfo(token_info):
    """
    Part of OIDC
    """
    return userinfo(token_info)


def post_userinfo(token_info):
    """
    Part of OIDC
    """
    return userinfo(token_info)


def cb():
    """
    Part of OIDC
    """
    query_params = request.args
    state = json.loads(base64.b64decode(query_params["state"]))
    openid_provider = Config.get_openid_provider()
    openid_config = get_openid_config(openid_provider)
    token_endpoint = openid_config["token_endpoint"]

    client_id = state.get("client_id")
    client_id = client_id if client_id != 'None' else None

    redirect_uri = state.get("redirect_uri")
    redirect_uri = redirect_uri if redirect_uri != 'None' else None
    # TODO need to parse the error message if login is required and redirect to login
    if query_params.get('error'):
        # redirect to authorize() if logging required
        ConnexionResponse(status_code=requests.codes.found, headers=dict(Location='/oauth/authorize'))
    elif redirect_uri and client_id:
        # OIDC proxy flow
        resp_params = dict(code=query_params["code"], state=state.get("state"))
        dest = furl(state["redirect_uri"]).add(resp_params).url
        return ConnexionResponse(status_code=requests.codes.found, headers=dict(Location=dest))
    else:
        # Simple flow
        oauth2_config = Config.get_oauth2_config()
        # Retrieve Access Token and authenticate user using OIDC
        res = requests.post(token_endpoint, dict(code=query_params["code"],
                                                 client_id=oauth2_config[openid_provider]["client_id"],
                                                 client_secret=oauth2_config[openid_provider]["client_secret"],
                                                 redirect_uri=oauth2_config[openid_provider]["redirect_uri"],
                                                 grant_type="authorization_code"))
        try:
            res.raise_for_status()
        except requests.exceptions.HTTPError:
            return make_response(res.text, res.status_code, res.headers.items())
        token_header = jwt.get_unverified_header(res.json()["id_token"])
        public_key = get_public_key(openid_provider, token_header["kid"])
        tok = jwt.decode(res.json()["id_token"],
                         key=public_key,
                         audience=oauth2_config[openid_provider]["client_id"])
        assert tok["email_verified"]  # TODO return a specific error when email is not verfied.

        headers = dict()
        resp = res.json()
        if state.get('cookie'):
            # Return the access token as a cookie.
            headers['set-cookie'] = ';'.join([f"access_token={resp.pop('access_token')}",
                                              "SameSite=Strict",
                                              "Domain=humancellatlas.org",
                                              "Secure",
                                              "HttpOnly",
                                              f"Max-Age={Config.cookie_age}",  # in seconds
                                              f"Expires={int(time.time()) + Config.cookie_age}",
                                              "path=/"])

        if redirect_uri:
            # Simple flow - redirect with QS
            resp_params = dict(resp, decoded_token=json.dumps(tok), state=state.get("state"))
            dest = furl(state["redirect_uri"]).add(resp_params).url
            headers['Location'] = dest
            return ConnexionResponse(status_code=requests.codes.found, headers=headers)
        else:
            # Simple flow - JSON
            headers.update(request.headers)
            return ConnexionResponse(status_code=requests.codes.ok,
                                     headers=headers,
                                     body={
                                         "query": query_params,
                                         "token_endpoint": token_endpoint,
                                         "res": resp,
                                         "tok": tok,
                                     })
