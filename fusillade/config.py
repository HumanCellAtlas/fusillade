import json
import os
import secrets
from datetime import timedelta

import boto3


class Config:
    _admin_emails: list = None
    _oauth2_config = None
    app = None
    audience = None
    _openid_provider = None
    version = "unversioned"
    directory_schema_version = {"Version": '0', "MinorVersion": '0'}
    _directory = None
    _directory_name = None
    group_max = 10
    oidc_email_claim = 'https://auth.data.humancellatlas.org/email'
    cookie_age = 600

    @classmethod
    def get_admin_emails(cls):
        if not cls._admin_emails:
            cls._admin_emails = [admin.strip() for admin in os.environ['FUS_ADMIN_EMAILS'].split(',') if admin.strip()]
            assert cls._admin_emails, "Initial administrator must be specified. Set FUS_ADMIN_EMAILS."
        return cls._admin_emails

    @classmethod
    def get_oauth2_config(cls):
        if not cls._oauth2_config:
            sm = boto3.client("secretsmanager")
            cls._oauth2_config = json.loads(
                sm.get_secret_value(
                    SecretId=f"{os.environ['FUS_SECRETS_STORE']}/"
                    f"{os.environ['FUS_DEPLOYMENT_STAGE']}/oauth2_config")["SecretString"])
            if 'localhost' in os.getenv('API_DOMAIN_NAME'):
                cls._oauth2_config[os.getenv('OPENID_PROVIDER')]['redirect_uri'] = f"http://" \
                    f"{os.getenv('API_DOMAIN_NAME')}/internal/cb"
        return cls._oauth2_config

    @classmethod
    def get_directory(cls):
        if not cls._directory:
            from fusillade import CloudDirectory
            directory_name = cls.get_directory_name()
            cls._directory = CloudDirectory.from_name(directory_name)
        return cls._directory

    @classmethod
    def get_directory_name(cls):
        if not cls._directory_name:
            cls._directory_name = os.getenv("FUSILLADE_DIR", f"hca_fusillade_{os.environ['FUS_DEPLOYMENT_STAGE']}")
        return cls._directory_name

    @classmethod
    def get_schema_name(cls):
        return f"hca_fusillade_base_{os.environ['FUS_DEPLOYMENT_STAGE']}"

    @classmethod
    def get_audience(cls):
        if not cls.audience:
            cls.audience = os.environ['FUS_AUDIENCE']
        return cls.audience

    @classmethod
    def get_openid_provider(cls):
        if not cls._openid_provider:
            cls._openid_provider = os.environ['OPENID_PROVIDER']
        return cls._openid_provider

    @classmethod
    def log_level(cls):
        return int(os.environ.get("DEBUG", "1"))

    @classmethod
    def get_flask_config(cls):
        return dict(
            SECRET_KEY=secrets.token_hex(32),
            DEBUG=Config.log_level() > 1,
            SESSION_COOKIE_HTTPONLY=True,
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_SAMESITE='Strict',
            # SESSION_COOKIE_DOMAIN='humancellatlas.org',
            PERMANENT_SESSION_LIFETIME=timedelta(hours=3),
            SESSION_REFRESH_EACH_REQUEST=True
        )


proj_path = os.path.dirname(__file__)
