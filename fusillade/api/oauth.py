'''
This module contains function to authenticate users using OpenId Connect
https://openid.net/connect/
'''
import base64
import os

import jwt
import requests
from flask import json, request, make_response
from connexion.lifecycle import ConnexionResponse
from furl import furl

from fusillade import Config
from fusillade.errors import FusilladeHTTPException
from fusillade.utils.security import get_openid_config, get_public_keys


def login():
    return ConnexionResponse(
        status_code=requests.codes.moved,
        headers=dict(Location='/oauth/authorize'))


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
                           state=state)
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
                         userinfo_endpoint=f"https://{os.environ['API_DOMAIN_NAME']}/oauth/userinfo"
                         )


def serve_openid_config():
    """
    Part of OIDC
    """
    openid_config = get_openid_config(Config.get_openid_provider())
    auth_host = request.headers['host']
    if auth_host != os.environ["API_DOMAIN_NAME"]:
        raise FusilladeHTTPException(
            status=400,
            title="Bad Request",
            detail=f"host: {auth_host}, is not supported. host must be {os.environ['API_DOMAIN_NAME']}.")
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
    openid_config = get_openid_config(Config.get_openid_provider())
    return proxy_response(openid_config["userinfo_endpoint"])


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
    if redirect_uri and client_id:
        # OIDC proxy flow
        resp_params = dict(code=query_params["code"], state=state.get("state"))
        dest = furl(state["redirect_uri"]).add(resp_params).url
        return ConnexionResponse(status_code=requests.codes.found, headers=dict(Location=dest))
    else:
        # Simple flow
        oauth2_config = Config.get_oauth2_config()
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
        public_keys = get_public_keys(openid_provider)
        tok = jwt.decode(res.json()["id_token"],
                         key=public_keys[token_header["kid"]],
                         audience=oauth2_config[openid_provider]["client_id"])
        assert tok["email_verified"]
        if redirect_uri:
            # Simple flow - redirect with QS
            resp_params = dict(res.json(), decoded_token=json.dumps(tok), state=state.get("state"))
            dest = furl(state["redirect_uri"]).add(resp_params).url
            return ConnexionResponse(status_code=requests.codes.found, headers=dict(Location=dest))
        else:
            # Simple flow - JSON
            return {
                "headers": dict(request.headers),
                "query": query_params,
                "token_endpoint": token_endpoint,
                "res": res.json(),
                "tok": tok,
            }
