from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ObjectDoesNotExist

from order_api.models import CustomUser
from order_api.utils.utils import decode_jwt


class JWTAuthMiddleware:
    def resolve(self, next, root, info, **kwargs):
        request = info.context
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')

        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            try:

                payload = decode_jwt(token)

                user = CustomUser.objects.get(oidc_id=payload['sub'])
                request.user = user
            except ObjectDoesNotExist as e:
                request.user = AnonymousUser()

        else:
            # If no valid Authorization header, set the user as anonymous
            request.user = AnonymousUser()

        # Proceed to the next resolver
        return next(root, info, **kwargs)
