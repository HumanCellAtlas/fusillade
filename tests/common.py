import json
import os
import time
import typing

import jwt
from dcplib.aws import clients

from fusillade.clouddirectory import publish_schema, create_directory, CloudDirectory
from fusillade.config import Config
from tests import schema_name, random_hex_string

test_account_file=f"{os.environ['FUS_HOME']}/test_accounts_{os.environ['FUS_DEPLOYMENT_STAGE']}.json"
try:
    with open(test_account_file, 'r') as fh:
        service_accounts = json.load(fh)
except FileNotFoundError:
    sm = clients.secretsmanager
    service_accounts = json.loads(
        sm.get_secret_value(SecretId=f"{os.environ['FUS_SECRETS_STORE']}/{os.environ['FUS_DEPLOYMENT_STAGE']}"
        f"/test_service_accounts")["SecretString"]
    )
    with open(test_account_file, 'w') as fh:
        json.dump(service_accounts, fh)


def create_test_statement(name: str, actions: typing.List[str] = None, json=False):
    """Assists with the creation of policy statements for testing"""
    statement = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DefaultRole",
                "Effect": "Deny",
                "Action": actions if actions else ["fake:action"],
                "Resource": "fake:resource"
            }
        ]
    }
    statement["Statement"][0]["Sid"] = name

    return statement if json else json.dumps(statement)


def create_test_statements(length=1):
    """Assists with the creation of policy statements for testing"""
    statement = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": [
                    "fake:action"
                ],
                "Resource": "fake:resource"
            } for i in range(length)
        ]
    }
    return json.dumps(statement)


def new_test_directory(directory_name=None) -> typing.Tuple[CloudDirectory, str]:
    directory_name = directory_name if directory_name else "test_dir_" + random_hex_string()
    schema_arn = publish_schema(schema_name, 'T' + random_hex_string())
    Config._directory = None
    Config._directory_name = None
    os.environ["FUSILLADE_DIR"] = directory_name
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
               'scope': ['email', 'openid', 'offline_access'],
               }
    if email:
        payload['https://auth.data.humancellatlas.org/email'] = service_credentials["client_email"]
    additional_headers = {'kid': service_credentials["private_key_id"]}
    signed_jwt = jwt.encode(payload, service_credentials["private_key"], headers=additional_headers,
                            algorithm='RS256').decode()
    return signed_jwt


def get_auth_header(service_credentials: dict, email=True):
    info = service_credentials
    token = get_service_jwt(info, email=email)
    return {"Authorization": f"Bearer {token}"}
