from django.contrib.auth.models import AnonymousUser

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
            except Exception as e:
                request.user = AnonymousUser()
        
        return next(root, info, **kwargs)