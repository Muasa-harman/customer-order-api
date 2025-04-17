from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
import os

User = get_user_model()

class KeycloakOIDCBackend(OIDCAuthenticationBackend):
    def get_userinfo(self, access_token, id_token, payload):
        """Return user details dictionary."""
        return self.verify_claims(self.get_claims(access_token))

    def create_user(self, claims):
        user = super().create_user(claims)
        return self._update_user(user, claims)

    def update_user(self, user, claims):
        return self._update_user(user, claims)

    def _update_user(self, user, claims):
        user.oidc_id = claims.get('sub')
        user.roles = claims.get('realm_access', {}).get('roles', [])
        user.save()
        return user

    def filter_users_by_claims(self, claims):
        sub = claims.get('sub')
        if not sub:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(oidc_id=sub)

    def verify_claims(self, claims):
        """Add custom claims validation"""
        verified = super().verify_claims(claims)
        if not claims.get('email_verified', False):
            raise ImproperlyConfigured("Email not verified")
        return verified




# from mozilla_django_oidc.auth import OIDCAuthenticationBackend

# class KeycloakOIDCBackend(OIDCAuthenticationBackend):
#     def create_user(self, claims):
#         user = super().create_user(claims)
#         user.oidc_id = claims.get('sub')
#         user.roles = claims.get('realm_access', {}).get('roles', [])
#         user.save()
#         return user

#     def update_user(self, user, claims):
#         user.oidc_id = claims.get('sub')
#         user.roles = claims.get('realm_access', {}).get('roles', [])
#         user.save()
#         return user

#     def filter_users_by_claims(self, claims):
#         sub = claims.get('sub')
#         return self.UserModel.objects.filter(oidc_id=sub)