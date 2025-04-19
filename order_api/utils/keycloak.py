# auth/backends.py
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

from keycloak import KeycloakOpenID


class KeycloakOIDCBackend(OIDCAuthenticationBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.keycloak_client = KeycloakOpenID(
            server_url=settings.KEYCLOAK_SERVER_URL,
            client_id=settings.OIDC_RP_CLIENT_ID,
            realm_name=settings.OIDC_RP_REALM_NAME,
            client_secret_key=settings.OIDC_RP_CLIENT_SECRET,
            verify=settings.OIDC_VERIFY_SSL
        )

    def get_userinfo(self, access_token, id_token, payload):
        """Return user details from Keycloak"""
        return self.keycloak_client.userinfo(access_token)

    def create_user(self, claims):
        """Create user from Keycloak claims"""
        user = super().create_user(claims)
        return self.update_user(user, claims)

    def update_user(self, user, claims):
        """Update user from Keycloak claims"""
        user.oidc_id = claims.get('sub')
        user.email = claims.get('email')
        user.phone = claims.get('phone')
        user.roles = claims.get('realm_access', {}).get('roles', [])
        user.save()
        return user

    def filter_users_by_claims(self, claims):
        """Find existing user by Keycloak sub ID"""
        sub = claims.get('sub')
        if not sub:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(oidc_id=sub)

    def verify_claims(self, claims):
        """Add custom claims validation"""
        if not super().verify_claims(claims):
            return False
        if not claims.get('email_verified', False):
            return False
        return True


# auth/client.py
from keycloak import KeycloakOpenID
from django.conf import settings


class KeycloakClient:
    def __init__(self):
        self.client = KeycloakOpenID(
            server_url=settings.KEYCLOAK_SERVER_URL,
            client_id=settings.OIDC_RP_CLIENT_ID,
            realm_name=settings.OIDC_RP_REALM_NAME,
            client_secret_key=settings.OIDC_RP_CLIENT_SECRET,
            verify=settings.OIDC_VERIFY_SSL
        )

    def get_auth_url(self, redirect_uri, state=None):
        return self.client.auth_url(
            redirect_uri=redirect_uri,
            scope='openid email profile',
            state=state
        )

    def get_tokens(self, code, redirect_uri):
        return self.client.token(
            grant_type='authorization_code',
            code=code,
            redirect_uri=redirect_uri
        )

# from mozilla_django_oidc.auth import OIDCAuthenticationBackend
# from django.contrib.auth import get_user_model
# from django.core.exceptions import ImproperlyConfigured
# from keycloak import KeycloakOpenID
# import os

# User = get_user_model()

# class KeycloakOIDCBackend(OIDCAuthenticationBackend):

#     def get_userinfo(self, access_token, id_token, payload):
#         """Return user details dictionary."""
#         return self.verify_claims(self.get_claims(access_token))

#     def create_user(self, claims):
#         user = super().create_user(claims)
#         return self._update_user(user, claims)

#     def update_user(self, user, claims):
#         return self._update_user(user, claims)

#     def _update_user(self, user, claims):
#         user.oidc_id = claims.get('sub')
#         user.roles = claims.get('realm_access', {}).get('roles', [])
#         user.save()
#         return user

#     def filter_users_by_claims(self, claims):
#         sub = claims.get('sub')
#         if not sub:
#             return self.UserModel.objects.none()
#         return self.UserModel.objects.filter(oidc_id=sub)

#     def verify_claims(self, claims):
#         """Add custom claims validation"""
#         verified = super().verify_claims(claims)
#         if not claims.get('email_verified', False):
#             raise ImproperlyConfigured("Email not verified")
#         return verified

# # keycloak interaction
# class KeycloakClient:
#     def __init__(self):
#         self.client = KeycloakOpenID(
#             server_url=settings.KEYCLOAK_SERVER_URL,
#             client_id=settings.OIDC_CLIENT_ID,
#             realm_name=settings.KEYCLOAK_REALM,
#             client_secret_key=settings.OIDC_CLIENT_SECRET,
#             verify=True
#         )

#     def get_auth_url(self, redirect_uri):
#         return self.client.auth_url(
#             redirect_uri=redirect_uri,
#             scope='openid email profile',
#             state='your_state_param'  
#         )

#     def get_tokens(self, code, redirect_uri):
#         return self.client.token(
#             grant_type='authorization_code',
#             code=code,
#             redirect_uri=redirect_uri
#         )
