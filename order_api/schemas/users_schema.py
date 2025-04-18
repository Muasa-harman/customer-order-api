import os
import graphene
from graphene_django import DjangoObjectType
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from graphql_jwt import ObtainJSONWebToken, Refresh, Verify
from keycloak import KeycloakOpenID, KeycloakAdmin
from phonenumber_field.phonenumber import PhoneNumber
from phonenumber_field.validators import validate_international_phonenumber
import requests
import traceback
from graphql import GraphQLError

from order_api.utils.utils import jwt_encode_handler, jwt_payload_handler

CustomUser = get_user_model()
class UserType(DjangoObjectType):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'phone', 'roles', 'oidc_id')

class KeycloakLoginResult(graphene.ObjectType):
    access_token = graphene.String()
    refresh_token = graphene.String()
    keycloak_access_token = graphene.String()
    user = graphene.Field(UserType)


class RegisterInput(graphene.InputObjectType):
    email = graphene.String(required=True)
    password = graphene.String(required=True)
    phone = graphene.String(required=True)

class KeycloakLoginInput(graphene.InputObjectType):
    code = graphene.String(required=True)
    redirect_uri = graphene.String(required=True)

class RegisterUser(graphene.Mutation):
    class Arguments:
        input = RegisterInput(required=True)

    user = graphene.Field(UserType)
    message = graphene.String()
    success = graphene.Boolean()
    errors = graphene.List(graphene.String)

    # @classmethod
    # def mutate(cls, root, info, input):
    #     try:
    #         # Phone validation
    #         phone = PhoneNumber.from_string(input.phone)
    #         validate_international_phonenumber(phone)

    #         # Check existing users
    #         if CustomUser.objects.filter(email=input.email).exists():
    #             raise ValidationError("Email already registered")
    #         if CustomUser.objects.filter(phone=phone).exists():
    #             raise ValidationError("Phone number already registered")

    #         # Initialize Keycloak Admin with proper configuration
    #         keycloak_admin = KeycloakAdmin(
    #             server_url=os.getenv('KEYCLOAK_SERVER_URL'),
    #             username=os.getenv('KEYCLOAK_ADMIN_USER'),
    #             password=os.getenv('KEYCLOAK_ADMIN_PASSWORD'),
    #             realm_name=os.getenv('KEYCLOAK_REALM'),
    #             client_id=os.getenv('OIDC_CLIENT_ID'),
    #             client_secret_key=os.getenv('OIDC_CLIENT_SECRET'),
    #             verify=True,
    #             # auto_refresh_token=['get', 'post', 'put', 'delete']
    #         )
            
    #         if keycloak_admin.get_users({"email": input.email}):
    #            raise ValidationError("Email exists in Keycloak")
          
    #         # Create Keycloak user
    #         user_id = keycloak_admin.create_user({
    #             "email": input.email,
    #             "username": input.email,
    #             "enabled": True,
    #             "credentials": [{
    #                 "type": "password",
    #                 "value": input.password,
    #                 "temporary": False
    #             }],
    #             "attributes": {"phone": str(phone)}
    #         })

            

    #         # Create local user
    #         user = CustomUser.objects.create_user(
    #             email=input.email,
    #             password=None,
    #             phone=phone,
    #             oidc_id=user_id
    #         )
    #         user.set_unusable_password()
    #         user.save()

    #         return RegisterUser(
    #             success=True,
    #             message="User registered successfully",
    #             user=user,
    #             errors=[]
    #         )
        
    #     except ValidationError as e:
    #         return RegisterUser(
    #             success=False,
    #             message="Validation error",
    #             user=None,
    #             errors=e.messages
    #         )
    #     except Exception as e:
    #         traceback.print_exc()
    #         return RegisterUser(
    #             success=False,
    #             message=str(e),
    #             user=None,
    #             errors=["Registration failed"]
    #         )
    @staticmethod
    def mutate(root, info, input):
        try:
            keycloak_openid = KeycloakOpenID(
                server_url=os.getenv('KEYCLOAK_SERVER_URL'),
                realm_name=os.getenv('KEYCLOAK_REALM'),
                client_id=os.getenv('OIDC_CLIENT_ID'),
                client_secret_key=os.getenv('OIDC_CLIENT_SECRET'),
            )

            # Fetch token
            token_response = keycloak_openid.token(
                grant_type='authorization_code',
                code=input.code,
                redirect_uri=input.redirect_uri,
            )
            if 'error' in token_response:
                raise graphene.GraphQLError(f"Keycloak error: {token_response['error_description']}")

            access_token = token_response['access_token']
            print("Access token:", access_token)

            # Fetch user info
            user_info = keycloak_openid.userinfo(access_token)
            print("User info:", user_info)

            # Decode token
            decoded_token = keycloak_openid.decode_token(access_token)
            print("Decoded token:", decoded_token)

            # Validate user info
            if not user_info.get('email'):
                raise graphene.GraphQLError("Email is missing in Keycloak user info.")

            # Create or update local user
            user, _ = CustomUser.objects.update_or_create(
                oidc_id=user_info['sub'],
                defaults={
                    'email': user_info.get('email'),
                    'phone': user_info.get('phone', ''),
                    'roles': decoded_token.get('realm_access', {}).get('roles', [])
                }
            )

            # Generate local JWT
            payload = jwt_payload_handler(user)
            local_token = jwt_encode_handler(payload)

            return KeycloakLoginResult(
                access_token=local_token,
                refresh_token=token_response.get('refresh_token'),
                keycloak_access_token=access_token,
                user=user
            )

        except Exception as e:
            traceback.print_exc()
            raise graphene.GraphQLError(f"Authentication failed: {str(e)}")


class LoginInput(graphene.InputObjectType):
    username = graphene.String(required=True)
    password = graphene.String(required=True)

class LoginResult(graphene.ObjectType):
    access_token = graphene.String()
    refresh_token = graphene.String()
    keycloak_access_token = graphene.String()
    user = graphene.Field(lambda: UserType)

class UserType(DjangoObjectType):
    class Meta:
        model = CustomUser
        fields = ('id', 'email', 'phone', 'roles', 'oidc_id')

class Login(graphene.Mutation):
    class Arguments:
        input = LoginInput(required=True)

    Output = LoginResult

    @staticmethod
    def mutate(root, info, input):
        try:
            # Initialize Keycloak client
            keycloak_openid = KeycloakOpenID(
                server_url=os.getenv('KEYCLOAK_SERVER_URL'),
                realm_name=os.getenv('KEYCLOAK_REALM'),
                client_id=os.getenv('OIDC_CLIENT_ID'),
                client_secret_key=os.getenv('OIDC_CLIENT_SECRET'),
            )

            
            token_response = keycloak_openid.token(
                grant_type='password',
                username=input.username,
                password=input.password,
            )

            if 'error' in token_response:
                raise GraphQLError(f"Keycloak error: {token_response['error_description']}")  # Corrected

            access_token = token_response['access_token']
            refresh_token = token_response['refresh_token']

            # Fetch user info from Keycloak
            user_info = keycloak_openid.userinfo(access_token)

            # Sync user with local database
            user, _ = CustomUser.objects.update_or_create(
                oidc_id=user_info['sub'],
                defaults={
                    'email': user_info.get('email'),
                    'phone': user_info.get('phone', ''),
                    'roles': user_info.get('realm_access', {}).get('roles', [])
                }
            )

            # Generate local JWT token
            payload = jwt_payload_handler(user)
            local_token = jwt_encode_handler(payload)

            return LoginResult(
                access_token=local_token,
                refresh_token=refresh_token,
                keycloak_access_token=access_token,
                user=user
            )

        except Exception as e:
            traceback.print_exc()
            raise GraphQLError(f"Login failed: {str(e)}")  

class AuthMutation(graphene.ObjectType):
    register = RegisterUser.Field()
    login = Login.Field() 
    refresh_token = Refresh.Field()
    verify_token = Verify.Field()


class AuthQuery(graphene.ObjectType):
    me = graphene.Field(UserType)

    def resolve_me(self, info):
        user = info.context.user
        if user.is_anonymous:
            raise GraphQLError('Not authenticated!') 
        return user

class Mutation(AuthMutation, graphene.ObjectType):
    pass

class Query(AuthQuery, graphene.ObjectType):
    pass

schema = graphene.Schema(query=Query, mutation=Mutation)

class AuthQuery(graphene.ObjectType):
    me = graphene.Field(UserType)

    def resolve_me(self, info):
        user = info.context.user
        if user.is_anonymous:
            raise graphene.GraphQLError('Not authenticated!')
        return user

class Mutation(AuthMutation, graphene.ObjectType):
    pass

class Query(AuthQuery, graphene.ObjectType):
    pass

schema = graphene.Schema(query=Query, mutation=Mutation)

