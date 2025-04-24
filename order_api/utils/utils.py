from jwt import decode, PyJWKClient, ExpiredSignatureError, InvalidTokenError


def decode_jwt(token):
    try:
        jwks_url = os.getenv(
            "OIDC_JWKS_URL") 
        audience = os.getenv("OIDC_CLIENT_ID")
        issuer = os.getenv("OIDC_ISSUER")

        jwk_client = PyJWKClient(jwks_url)
        signing_key = jwk_client.get_signing_key_from_jwt(token)

        decoded = decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer
        )
        return decoded
    except ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except InvalidTokenError as e:
        raise ValueError(f"Invalid JWT token: {str(e)}")


from datetime import datetime
import os
from django.conf import settings


def get_jwt_secret():
    return settings.SECRET_KEY


def jwt_payload_handler(user, context=None):
    return {
        'user_id': user.id,
        'email': user.email,
        'roles': user.roles,
        'exp': datetime.utcnow() + settings.JWT_EXPIRATION_DELTA,
        'iss': os.getenv('OIDC_ISSUER'),
        'aud': os.getenv('OIDC_CLIENT_ID')
    }

