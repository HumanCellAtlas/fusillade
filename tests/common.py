import json
import os
import time

import jwt
from dcplib.aws import clients
from tests import schema_name, random_hex_string
from fusillade.config import Config
from fusillade.clouddirectory import publish_schema, create_directory, CloudDirectory


sm = clients.secretsmanager
service_accounts = json.loads(
    sm.get_secret_value(SecretId=f"{os.environ['FUS_SECRETS_STORE']}/test_service_accounts")["SecretString"]
)


def create_test_statement(name: str):
    """Assists with the creation of policy statements for testing"""
    statement = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DefaultRole",
                "Effect": "Deny",
                "Action": [
                    "fake:action"
                ],
                "Resource": "fake:resource"
            }
        ]
    }
    statement["Statement"][0]["Sid"] = name
    return json.dumps(statement)


def new_test_directory(directory_name=None) -> CloudDirectory:
    directory_name = directory_name if directory_name else "test_dir_" + random_hex_string()
    schema_arn = publish_schema(schema_name, 'T' + random_hex_string())
    directory = create_directory(directory_name, schema_arn, [service_accounts['admin']['client_email']])
    return directory, schema_arn


def get_service_jwt(service_credentials, email=True, audience=None):
    iat = time.time()
    exp = iat + 3600
    payload = {'iss': service_credentials["client_email"],
               'sub': service_credentials["client_email"],
               'aud': audience or Config.audience,
               'iat': iat,
               'exp': exp,
               'scope': ['email', 'openid', 'offline_access']
               }
    if email:
        payload['email'] = service_credentials["client_email"]
    additional_headers = {'kid': service_credentials["private_key_id"]}
    signed_jwt = jwt.encode(payload, service_credentials["private_key"], headers=additional_headers,
                            algorithm='RS256').decode()
    return signed_jwt


def get_auth_header(service_credentials: dict, email=True):
    info = service_credentials
    token = get_service_jwt(info, email=email)
    return {"Authorization": f"Bearer {token}"}

