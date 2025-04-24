import os
from typing import Dict, Any

from graphql import GraphQLError
from keycloak import KeycloakOpenID


def load_keycloak_user_info(auth_header: str) -> Dict[str, Any]:
    try:
      
        if not auth_header or not auth_header.startswith('Bearer '):
            raise GraphQLError('Invalid authorization header')

        # Extract token
        token = auth_header.split(' ')[1]

        # Initialize Keycloak client
        keycloak_client = KeycloakOpenID(
            server_url=os.getenv('KEYCLOAK_SERVER_URL'),
            realm_name=os.getenv('KEYCLOAK_REALM'),
            client_id=os.getenv('OIDC_CLIENT_ID'),
            client_secret_key=os.getenv('OIDC_CLIENT_SECRET')
        )

        # Get user info and decode token
        user_info = keycloak_client.userinfo(token)
        decoded_token = keycloak_client.decode_token(token)

        # Extract roles from token
        roles = decoded_token.get('realm_access', {}).get('roles', [])

        # Combine user info
        complete_user_info = {
            'sub': user_info.get('sub'),
            'email': user_info.get('email'),
            'given_name': user_info.get('given_name'),
            'family_name': user_info.get('family_name'),
            'phone_number': user_info.get('phone_number'),
            'roles': roles,
            'preferred_username': user_info.get('preferred_username'),
            'email_verified': user_info.get('email_verified', False),
            'full_name': f"{user_info.get('given_name', '')} {user_info.get('family_name', '')}".strip()
        }

        return complete_user_info

    except Exception as e:
        print(e)
        raise GraphQLError(f'Failed to load user information: {str(e)}')
