#!/usr/bin/env python3.6
"""
Used by connexion to verify the JWT in Authorization header of the request.
"""
import base64
import functools
import logging
import typing

import jwt
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from fusillade import Config
from fusillade.errors import FusilladeHTTPException

logger = logging.getLogger(__name__)

allowed_algorithms = ['RS256']
gserviceaccount_domain = "iam.gserviceaccount.com"

# recycling the same session for all requests.
session = requests.Session()

openid_config = dict()

def get_openid_config(openid_provider: str) -> dict:
    """

    :param openid_provider: the openid provider's domain.
    :return: the openid configuration
    """
    if openid_provider not in openid_config:
        if openid_provider.endswith(gserviceaccount_domain):
            openid_provider = 'accounts.google.com'
        else:
            openid_provider = Config.get_openid_provider()
        res = requests.get(f"https://{openid_provider}/.well-known/openid-configuration")
        res.raise_for_status()
        openid_config[openid_provider] = res.json()
        logger.info({'message': "caching", 'openid_provider': {openid_provider: openid_config[openid_provider]}})
    return openid_config[openid_provider]


def get_jwks_uri(openid_provider) -> str:
    if openid_provider.endswith(gserviceaccount_domain):
        return f"https://www.googleapis.com/service_accounts/v1/jwk/{openid_provider}"
    else:
        return get_openid_config(openid_provider)["jwks_uri"]


@functools.lru_cache(maxsize=32)
def get_public_keys(issuer: str) -> typing.Dict[str, bytearray]:
    """
    Fetches the public keys from an OIDC Identity provider to verify the JWT and caching for later use.
    :param issuer: the openid provider's domain.
    :param kid: the key identifier for verifying the JWT
    :return: A Public Keys
    """
    resp = session.get(get_jwks_uri(issuer))
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        logger.error({"message": f"Get {get_jwks_uri(issuer)} Failed",
                      "text": resp.text,
                      "status_code": resp.status_code,
                      })
        raise FusilladeHTTPException(503, 'Service Unavailable', "Failed to fetched public key from openid provider.")
    else:
        logger.info({
            "message": f"Get {get_jwks_uri(issuer)} Succeeded",
            "response": resp.json(),
            "status_code": resp.status_code
        })

    return {
        key["kid"]: rsa.RSAPublicNumbers(
            e=int.from_bytes(base64.urlsafe_b64decode(key["e"] + "==="), byteorder="big"),
            n=int.from_bytes(base64.urlsafe_b64decode(key["n"] + "==="), byteorder="big")
        ).public_key(backend=default_backend())
        for key in resp.json()["keys"]
    }


def get_public_key(issuer: str, kid: str) -> bytearray:
    """
    Fetches the public keys from an OIDC Identity provider to verify the JWT. If the key is not found in the public
    key cache, the cache is cleared and a retry is performed.
    :param issuer: the openid provider's domain.
    :param kid: the key identifier for verifying the JWT
    :return: A Public Key
    """
    public_keys = get_public_keys(issuer)
    try:
        return public_keys[kid]
    except KeyError:
        logger.error({"message": "Failed to fetched public key from openid provider.",
                      "public_keys": public_keys,
                      "issuer": issuer,
                      "kid": kid})
        logger.debug({"message": "Clearing public key cache."})
        get_public_keys.cache_clear()
        public_keys = get_public_keys(issuer)
        try:
            return public_keys[kid]
        except KeyError:
            raise FusilladeHTTPException(401,
                                         'Unauthorized',
                                         f"Unable to verify JWT. KID:{kid} does not exists for issuer:{issuer}.")


def verify_jwt(token: str) -> typing.Optional[typing.Mapping]:
    """
    Verify the JWT from the request. This is function is referenced in fusillade-api.yml
    securitySchemes.BearerAuth.x-bearerInfoFunc. It's used by connexion to authorize api endpoints that use BearAuth
    securitySchema.

    :param token: the Authorization header in the request.
    :return: Decoded and verified token.
    """
    try:
        unverified_token = jwt.decode(token, verify=False)
        token_header = jwt.get_unverified_header(token)
    except jwt.DecodeError:
        logger.debug({"msg": "Failed to decode token."}, exc_info=True)
        raise FusilladeHTTPException(401, 'Unauthorized', 'Failed to decode token.')

    issuer = unverified_token['iss']
    public_key = get_public_key(issuer, token_header["kid"])
    try:
        verified_tok = jwt.decode(token,
                                  key=public_key,
                                  issuer=issuer,
                                  audience=Config.get_audience(),
                                  algorithms=allowed_algorithms,
                                  )
        logger.debug({"message": "Token Validated"})
    except jwt.PyJWTError as ex:  # type: ignore
        logger.debug({"message": "Failed to validate token."}, exc_info=True)
        raise FusilladeHTTPException(401, 'Unauthorized', 'Authorization token is invalid') from ex
    return verified_tok
