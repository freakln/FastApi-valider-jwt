import base64
import json
import os

import jwt
from .jwksutils import rsa_pem_from_jwk


class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__('Invalid authorization token: ' + details)


def get_unverified_header(token):
    jwts = token.split('.')
    return json.loads(base64.b64decode(jwts[0] + '==').decode("utf-8"))


def validate_jwt(jwt_to_validate):
    alg = get_alg(jwt_to_validate)  # RS256
    public_key = get_public_key(jwt_to_validate)

    jwt_decoded = jwt.decode(jwt_to_validate,
                             public_key,
                             verify=True,
                             algorithms=[alg],
                             audience=[os.environ["valid_audiences"]],
                             issuer=os.environ["issuer"])

    # do what you wish with decoded token:
    # if we get here, the JWT is validated
    return jwt_decoded


def get_jwt_value(token, key):
    headers = get_unverified_header(token)  # jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('missing headers')
    try:
        return headers[key]
    except KeyError:
        raise InvalidAuthorizationToken('missing ' + key)


def get_kid(token):
    headers = get_unverified_header(token)  # jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('missing headers')
    try:
        return headers['kid']
    except KeyError:
        raise InvalidAuthorizationToken('missing kid')


def get_alg(token):
    headers = get_unverified_header(token)  # jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken('missing headers')
    try:
        return headers['alg']
    except KeyError:
        raise InvalidAuthorizationToken('missing alg')


def get_jwk(kid):
    jwt_obj = json.loads(os.environ["jwt_keys"])
    for jwk in jwt_obj['keys']:
        if jwk['kid'] == kid:
            return jwk
    raise InvalidAuthorizationToken('kid not recognized')


def get_public_key(token):
    return rsa_pem_from_jwk(get_jwk(get_kid(token)))
