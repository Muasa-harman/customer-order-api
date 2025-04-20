from jwt import decode, PyJWKClient, ExpiredSignatureError, InvalidTokenError


def decode_jwt(token):
    try:
        jwks_url = os.getenv(
            "OIDC_JWKS_URL")  # e.g., http://localhost:8080/realms/myrealm/protocol/openid-connect/certs
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

#     class CreateOrder(graphene.Mutation):
#     class Arguments:
#         input = OrderInput(required=True)

#     order = graphene.Field(OrderType)
#     success = graphene.Boolean()
#     message = graphene.String()
#     errors = graphene.List(graphene.String)

#     @classmethod
#     def mutate(cls, root, info, input):
#         try:
#             # Extract token from headers
#             auth_header = info.context.headers.get('Authorization')
#             if not auth_header or not auth_header.startswith('Bearer '):
#                 raise GraphQLError("Authorization token is missing or invalid.")

#             token = auth_header.split(' ')[1]

#             # Validate the token
#             try:
#                 decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
#             except jwt.ExpiredSignatureError:
#                 raise GraphQLError("Token has expired.")
#             except jwt.InvalidTokenError:
#                 raise GraphQLError("Invalid token.")

#             # Extract user information from the token
#             user_id = decoded_token.get('user_id')
#             email = decoded_token.get('email')
#             roles = decoded_token.get('roles', [])

#             if not user_id or not email:
#                 raise GraphQLError("Invalid token payload: user_id or email is missing.")

#             # # Check user roles or permissions
#             # if 'customer' not in roles and 'admin' not in roles:
#             #     raise GraphQLError("You do not have permission to create an order.")

#             # Ensure the customer exists
#             try:
#                 customer = Customer.objects.get(email=email)
#             except Customer.DoesNotExist:
#                 raise GraphQLError("Customer associated with this token does not exist.")

#             # Validate order input
#             if input.quantity < 1:
#                 raise ValidationError('Quantity must be at least 1.')

#             if not input.item.strip():
#                 raise ValidationError("Item cannot be empty.")

#             if input.unit_price <= 0:
#                 raise ValidationError("Price must be greater than 0.")

#             # Create the order
#             order = Order(
#                 customer=customer,
#                 item=input.item,
#                 quantity=input.quantity,
#                 unit_price=input.unit_price
#             )
#             order.full_clean()
#             order.save()

#             return CreateOrder(
#                 order=order,
#                 success=True,
#                 message="Order created successfully!",
#                 errors=[]
#             )

#         except ValidationError as e:
#             return CreateOrder(
#                 order=None,
#                 success=False,
#                 message="Validation failed.",
#                 errors=e.messages
#             )
#         except Exception as e:
#             return CreateOrder(
#                 order=None,
#                 success=False,
#                 message="An error occurred.",
#                 errors=[str(e)]
#             )  i need from datetime import datetime, timedelta
# import os
# from django.conf import settings
# from jose import ExpiredSignatureError, jwt
# from jose.exceptions import JWTError

# def get_jwt_secret():
#     return settings.SECRET_KEY

# def jwt_payload_handler(user, context=None):
#     return {
#         'user_id': user.id,
#         'email': user.email,
#         'roles': user.roles,
#         'exp': datetime.utcnow() + settings.JWT_EXPIRATION_DELTA,
#         'iss': os.getenv('OIDC_ISSUER'),
#         'aud': os.getenv('OIDC_CLIENT_ID')
#     }

# def jwt_encode_handler(payload):
#     return jwt.encode(
#         payload,
#         get_jwt_secret(),
#         algorithm='HS256'
#     )

# def decode_jwt(token):
#     try:
#         return jwt.decode(
#             token,
#             get_jwt_secret(),
#             audience=os.getenv('OIDC_CLIENT_ID'),
#             issuer=os.getenv('OIDC_ISSUER'),
#             algorithms=['HS256']
#         )
#     except ExpiredSignatureError:
#       raise ValueError("Token has expired.")
#     except jwt.JWTClaimsError:
#      raise ValueError("Invalid claims in token.")
#     except JWTError:
#      raise ValueError("Invalid JWT token.")  token
