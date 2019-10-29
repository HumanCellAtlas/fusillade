"""
Sets the Auth0 API key in AWS secrets manager
"""
import json
import logging
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, Hash

from dcplib.aws_secret import AwsSecret
from fusillade.errors import FusilladeHTTPException

logger = logging.getLogger(__name__)

api_keys = AwsSecret('/'.join([os.environ['FUS_SECRETS_STORE'],
                               os.environ['FUS_DEPLOYMENT_STAGE'],
                               'api_keys']))


def hash(key: bytearray) -> bytearray:
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(key)
    return digest.finalize().hex()


def generate_api_key():
    from os import urandom

    # Generate key
    key = urandom(32)
    digest = hash(key)
    prefix = key.hex()[:7]  # grab first 7 characters
    return key.hex(), {
        prefix: {
            "description": "API key used to by Auth0 to access Fusillade.",
            "hash": digest,
        }
    }


def verify_api_key(key: str):
    try:
        expected = json.loads(api_keys.value)[key[:7]]['hash']
    except RuntimeError as ex:
        logger.debug({"message": "Failed to validate token. Secret does not exist."}, exc_info=True)
        raise FusilladeHTTPException(401, 'Unauthorized', 'Authorization token is invalid') from ex
    except KeyError as ex:
        logger.debug({"message": "Failed to validate token. Key does not exist."}, exc_info=True)
        raise FusilladeHTTPException(401, 'Unauthorized', 'Authorization token is invalid') from ex
    else:
        if expected != bytearray.fromhex(key):
            logger.debug({"message": "Failed to validate token. Invalid API key"}, exc_info=True)
            raise FusilladeHTTPException(401, 'Unauthorized', 'Authorization token is invalid')
