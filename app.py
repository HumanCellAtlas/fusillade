import os
import sys

import yaml
from botocore.vendored import requests
from chalice import Response as chalice_response
from flask import json

pkg_root = os.path.abspath(os.path.join(os.path.dirname(__file__), 'chalicelib'))
sys.path.insert(0, pkg_root)  # noqa

from fusillade import Config
from fusillade.api import FusilladeServer


with open(os.path.join(pkg_root, "service_config.json")) as fh:
    service_config = yaml.load(fh.read())

swagger_spec_path = os.path.join(pkg_root, "fusillade-api.yml")
app = FusilladeServer(app_name='fusillade', swagger_spec_path=swagger_spec_path)
Config.app = app


@app.route("/")  # TODO use connexion swagger ui and remove
def serve_swagger_ui():
    with open(os.path.join(pkg_root, "index.html")) as fh:
        swagger_ui_html = fh.read()
    return chalice_response(status_code=requests.codes.ok,
                            headers={"Content-Type": "text/html"},
                            body=swagger_ui_html)


@app.route("/version")  # version of the service
def version():
    data = {
        'version_info': {
            'version': 0.0
        }
    }
    return chalice_response(
        status_code=requests.codes.ok,
        headers={'Content-Type': "application/json"},
        body=data
    )


@app.route("/internal/status")
def health_check(*args, **kwargs):
    health_status = 'OK'
    return chalice_response(status_code=200,
                            headers={"Content-Type": "application/json"},
                            body=json.dumps(health_status, indent=4, sort_keys=True, default=str))


@app.route('/swagger.json')
def serve_swagger_definition():
    with open(swagger_spec_path) as fh:
        swagger_defn = yaml.load(fh.read())
    return swagger_defn


@app.route('/echo')
def echo():
    return str(app.current_request.__dict__)
