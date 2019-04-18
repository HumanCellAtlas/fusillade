import requests
from flask import make_response



def get():
    return make_response("", requests.codes.moved, dict(Location="/authorize"))
