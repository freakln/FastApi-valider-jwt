import json
import requests
import os

from azure.jwt_service import validate_jwt

jwt_keys = {}


def initWellKnownConfig(url):
    # get the well known info & get the public keys
    resp = requests.get(url=url)
    well_known_openid_config_data = resp.json()
    jwt_uri = well_known_openid_config_data['jwks_uri']
    # get the discovery keys
    resp = requests.get(url=jwt_uri)
    os.environ["jwt_keys"] = json.dumps(resp.json())


def init_azure_ad(self, client):
    os.environ["issuer"] = 'https://login.microsoftonline.com/' + self + "/v2.0"
    os.environ["valid_audiences"] = client
    initWellKnownConfig('https://login.microsoftonline.com/' + self + '/v2.0/.well-known/openid-configuration')


def checkAuthorization(token, scope=None):
    # Authorization: Bearer AbCdEf123456
    if token is None or not token.startswith("Bearer "):
        msg = 'Unauthorized. No or wrong token received in request'
        return True, {'error': msg, 'status': 401, 'mimetype': 'application/json'}

    try:
        jwt_decoded = validate_jwt(token[7:])
    except Exception as ex:
        msg = {"message": 'Unauthorized. Token is invalid. ' + ex.args[0]}
        return True, {'error': msg, 'status': 401, 'mimetype': 'application/json'}
    else:
        if scope is not None and len(scope) > 0:
            jwt_scopes = jwt_decoded['scp'].split()
            if scope not in jwt_scopes:
                msg = {"message": 'Unauthorized. Required scope(s) missing: ' + scope}
                return True, {'error': msg, 'status': 401, 'mimetype': 'application/json'}

    return False, jwt_decoded
