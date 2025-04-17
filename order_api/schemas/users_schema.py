import os
import graphene
from graphene_django import DjangoObjectType
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from graphql_jwt import ObtainJSONWebToken, Refresh, Verify
from keycloak import KeycloakOpenID
from phonenumber_field.phonenumber import PhoneNumber
from phonenumber_field.validators import validate_international_phonenumber

from order_api.utils.utils import jwt_encode_handler, jwt_payload_handler

CustomUser = get_user_model()

class UserType(DjangoObjectType):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'phone', 'roles','oidc_id')


class RegisterInput(graphene.InputObjectType):
    email = graphene.String(required=True)
    password = graphene.String(required=True)
    phone = graphene.String(required=True)


class RegisterUser(graphene.Mutation):
    class Arguments:
        input = RegisterInput(required=True)

    user = graphene.Field(UserType)
    success = graphene.Boolean()
    errors = graphene.List(graphene.String)
    message = graphene.String()

    @classmethod
    def mutate(cls, root, info, input):
        try:
            # Validate phone number
            phone = PhoneNumber.from_string(input.phone)
            validate_international_phonenumber(phone)

            if CustomUser.objects.filter(email=input.email).exists():
                raise ValidationError("Email already registered")

            if CustomUser.objects.filter(phone=phone).exists():
                raise ValidationError("Phone number already registered")

            user = CustomUser.objects.create_user(
                email=input.email,
                password=input.password,
                phone=input.phone
            )

            return RegisterUser(
                success=True,
                message="User registered successfully",
                user=user,
                errors=[]
            )

        except ValidationError as e:
            return RegisterUser(
                success=False,
                message="Validation error",
                user=None,
                errors=e.messages
            )
        except Exception as e:
            return RegisterUser(
                success=False,
                message=str(e),
                user=None,
                errors=["Registration failed"]
            )

# login
class UserType(DjangoObjectType):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'phone', 'roles')

class LoginInput(graphene.InputObjectType):
    email = graphene.String(required=True)
    password = graphene.String(required=True)

class KeycloakLoginInput(graphene.InputObjectType):
    code = graphene.String(required=True)
    redirect_uri = graphene.String(required=True)

class AuthMutation(graphene.ObjectType):
    # Standard email/password login
    login = graphene.Field(
        graphene.String,
        input=LoginInput(required=True),
        description="Authenticate with email/password"
    )
    
    # Keycloak OIDC login
    keycloak_login = graphene.Field(
        graphene.JSONString,
        input=KeycloakLoginInput(required=True),
        description="Authenticate with Keycloak OIDC"
    )

    @staticmethod
    def resolve_login(root, info, input):
        user = CustomUser.objects.filter(email=input.email).first()
        if user and user.check_password(input.password):
            # Generate JWT token
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)
            return token
        raise graphene.JSONWebTokenError('Invalid credentials')

    @staticmethod
    def resolve_keycloak_login(root, info, input):
        try:
            # Initialize Keycloak client
            keycloak_openid = KeycloakOpenID(
                server_url=os.getenv('OIDC_ISSUER'),
                client_id=os.getenv('OIDC_CLIENT_ID'),
                realm_name='master',
                client_secret=os.getenv('OIDC_CLIENT_SECRET'),
            )

            # Exchange code for tokens
            tokens = keycloak_openid.token(
                grant_type="authorization_code",
                code=input.code,
                redirect_uri=input.redirect_uri
            )

            # Get user info from Keycloak
            user_info = keycloak_openid.userinfo(tokens['access_token'])
            
            # Create or update local user
            user, created = CustomUser.objects.update_or_create(
                oidc_id=user_info['sub'],
                defaults={
                    'email': user_info.get('email'),
                    'roles': user_info.get('realm_access', {}).get('roles', [])
                }
            )

            # Generate JWT token for local API access
            payload = jwt_payload_handler(user)
            token = jwt_encode_handler(payload)

            return {
                'access_token': token,
                'refresh_token': tokens.get('refresh_token'),
                'keycloak_access_token': tokens['access_token'],
                'user': {
                    'email': user.email,
                    'roles': user.roles
                }
            }
        
        except Exception as e:
            raise graphene.JSONWebTokenError(f"Authentication failed: {str(e)}")

class Mutation(AuthMutation, graphene.ObjectType):
    pass



class AuthQuery(graphene.ObjectType):
    me = graphene.Field(UserType)

    def resolve_me(self, info):
        user = info.context.user
        if user.is_anonymous:
            raise Exception('Not authenticated!')
        return user


class AuthMutation(graphene.ObjectType):
    register = RegisterUser.Field()
    login = graphene.Field(  # Changed from token_auth
        graphene.String,
        input=LoginInput(required=True)
    )
    keycloak_login = graphene.Field(
        graphene.JSONString,
        input=KeycloakLoginInput(required=True)
    )
    refresh_token = Refresh.Field()
    verify_token = Verify.Field() 



class Mutation(AuthMutation, graphene.ObjectType):
    pass


