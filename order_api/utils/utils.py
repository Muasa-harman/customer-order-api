from datetime import datetime, timedelta
import os
from django.conf import settings
from jose import ExpiredSignatureError, jwt
from jose.exceptions import JWTError

def get_jwt_secret():
    return settings.SECRET_KEY

def jwt_payload_handler(user, context=None):
    return {
        'user_id': user.id,
        'email': user.email,
        # 'roles': user.roles,
        'exp': datetime.utcnow() + settings.JWT_EXPIRATION_DELTA,
        'iss': os.getenv('OIDC_ISSUER'),
        'aud': os.getenv('OIDC_CLIENT_ID')
    }

def jwt_encode_handler(payload):
    return jwt.encode(
        payload,
        get_jwt_secret(),
        algorithm='HS256'
    )

def decode_jwt(token):
    try:
        return jwt.decode(
            token,
            get_jwt_secret(),
            audience=os.getenv('OIDC_CLIENT_ID'),
            issuer=os.getenv('OIDC_ISSUER'),
            algorithms=['HS256']
        )
    except ExpiredSignatureError:
      raise ValueError("Token has expired.")
    except jwt.JWTClaimsError:
     raise ValueError("Invalid claims in token.")
    except JWTError:
     raise ValueError("Invalid JWT token.")