import requests
from connexion.lifecycle import ConnexionResponse


def get():
    return ConnexionResponse(status_code=requests.codes.moved, headers=dict(Location="/oauth/authorize"))
