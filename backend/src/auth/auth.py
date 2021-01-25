import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'alblowi12.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffie'

## AuthError Exception
# -----------------------------------------------------------------------------
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header
# -----------------------------------------------------------------------------
# Defining function to obtain authorization token from request header
def get_token_auth_header():
    '''Obtains access token from the Authoization header'''
    # Getting auth info from header
    auth = request.headers.get('Authorization', None)

    # Checking to see if auth information is present, else raises 401 error
    if not auth:
       raise AuthError({
           'code': 'authorization_header_missing',
           'description': 'Authorization header is expected.'
       }, 401)

    # Splitting out parts of auth header
    parts = auth.split()

    # Checking if 'parts' info looks as we would expect it to
    if parts[0].lower() != 'bearer':
       raise AuthError({
           'code': 'invalid_header',
           'description': 'Authoization header must start with "Bearer".'
       }, 401)
    elif len(parts) == 1:
       raise AuthError({
           'code': 'invalid_header',
           'description': 'Token not found.'
       }, 401)

    # Grabbing token from auth parts
    token = parts[1]

    return token



# Defining function to check if user has proper permissions given auth credentials
def check_permissions(permission, payload):
    # Checking to see if permissions are included in JWT
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not found in JWT.'
        }, 400)

    # Checking to see if permission from JWT matches what's available in general
    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not authorized.'
        }, 403)

    # If all checks out from above, return true
    return True



# Defining a function to check that the provided token matches what is expected from Auth0
def verify_decode_jwt(token):
    # Getting the public key from Auth0
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    # Getting header information from the provided token
    unverified_header = jwt.get_unverified_header(token)

    # Instantiating empty object to append RSA key info to
    rsa_key = {}

    # Checking to see if 'kid' is in the unverified header
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    # Appending information to RSA key dictionary from jwks if 'kid' matches the unverified header
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    # Getting payload information from the token using key if everything checks out fine (else raises error)
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        # Handling respective error scenarios
        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)
        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please check the autdience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    # If RSA_key info not present, raising AuthError
    raise AuthError({
        'code': 'invalid_header',
        'description': 'Unable to find appropriate key.'
    }, 400)


# Defining a function to create a nice Python decorator to easily ensure if auhtoirzation info is present
# before allowing user to perform any activities.
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            try:
                payload = verify_decode_jwt(token)
            except:
                raise AuthError({
                    'code': 'invalid_token',
                    'description': 'Token could not be verified.'
                }, 401)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator