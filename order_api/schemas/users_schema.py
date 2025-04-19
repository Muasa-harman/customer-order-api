import os
from keycloak import KeycloakOpenID
import graphene
from graphql import GraphQLError


class UserInfoType(graphene.ObjectType):
    email = graphene.String()
    phone = graphene.String()
    roles = graphene.List(graphene.String)
    sub = graphene.String()
    given_name = graphene.String()
    family_name = graphene.String()


class LoginInput(graphene.InputObjectType):
    username = graphene.String(required=True)
    password = graphene.String(required=True)


class LoginResult(graphene.ObjectType):
    access_token = graphene.String()
    refresh_token = graphene.String()
    user_info = graphene.Field(UserInfoType)
    success = graphene.Boolean()
    message = graphene.String()


class Login(graphene.Mutation):
    class Arguments:
        input = LoginInput(required=True)

    Output = LoginResult

    @staticmethod
    def mutate(root, info, input):
        try:
            keycloak_client = KeycloakOpenID(
                server_url=os.getenv('KEYCLOAK_SERVER_URL'),
                realm_name=os.getenv('KEYCLOAK_REALM'),
                client_id=os.getenv('OIDC_CLIENT_ID'),
                client_secret_key=os.getenv('OIDC_CLIENT_SECRET')
            )

            # Get token from Keycloak
            token_response = keycloak_client.token(
                grant_type='password',
                username=input.username,
                password=input.password
            )

            if 'error' in token_response:
                raise GraphQLError(f"Authentication failed: {token_response.get('error_description')}")

            access_token = token_response['access_token']
            refresh_token = token_response['refresh_token']

            # Get user info from Keycloak
            user_info = keycloak_client.userinfo(access_token)
            decoded_token = keycloak_client.decode_token(access_token)
            roles = decoded_token.get('realm_access', {}).get('roles', [])

            return LoginResult(
                success=True,
                message="Login successful",
                access_token=access_token,
                refresh_token=refresh_token,
                user_info=UserInfoType(
                    email=user_info.get('email'),
                    phone=user_info.get('phone_number'),
                    roles=roles,
                    sub=user_info.get('sub'),
                    given_name=user_info.get('given_name'),
                    family_name=user_info.get('family_name')
                )
            )

        except Exception as e:
            return LoginResult(
                success=False,
                message=str(e),
                access_token=None,
                refresh_token=None,
                user_info=None
            )


class RefreshTokenInput(graphene.InputObjectType):
    refresh_token = graphene.String(required=True)


class RefreshTokenResult(graphene.ObjectType):
    access_token = graphene.String()
    refresh_token = graphene.String()
    success = graphene.Boolean()
    message = graphene.String()


class RefreshToken(graphene.Mutation):
    class Arguments:
        input = RefreshTokenInput(required=True)

    Output = RefreshTokenResult

    @staticmethod
    def mutate(input):
        try:
            keycloak_client = KeycloakOpenID(
                server_url=os.getenv('KEYCLOAK_SERVER_URL'),
                realm_name=os.getenv('KEYCLOAK_REALM'),
                client_id=os.getenv('OIDC_CLIENT_ID'),
                client_secret_key=os.getenv('OIDC_CLIENT_SECRET')
            )

            # Refresh token
            token_response = keycloak_client.refresh_token(input.refresh_token)

            return RefreshTokenResult(
                success=True,
                message="Token refreshed successfully",
                access_token=token_response['access_token'],
                refresh_token=token_response['refresh_token']
            )

        except Exception as e:
            return RefreshTokenResult(
                success=False,
                message=str(e),
                access_token=None,
                refresh_token=None
            )


class Query(graphene.ObjectType):
    user_info = graphene.Field(UserInfoType)

    def resolve_user_info(self, info):
        try:
            auth_header = info.context.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                raise GraphQLError('Invalid authorization header')

            token = auth_header.split(' ')[1]

            keycloak_client = KeycloakOpenID(
                server_url=os.getenv('KEYCLOAK_SERVER_URL'),
                realm_name=os.getenv('KEYCLOAK_REALM'),
                client_id=os.getenv('OIDC_CLIENT_ID'),
                client_secret_key=os.getenv('OIDC_CLIENT_SECRET')
            )

            # Verify token and get user info
            user_info = keycloak_client.userinfo(token)
            decoded_token = keycloak_client.decode_token(token)
            roles = decoded_token.get('realm_access', {}).get('roles', [])

            return UserInfoType(
                email=user_info.get('email'),
                phone=user_info.get('phone_number'),
                roles=roles,
                sub=user_info.get('sub'),
                given_name=user_info.get('given_name'),
                family_name=user_info.get('family_name')
            )

        except Exception as e:
            raise GraphQLError(f'Failed to get user info: {str(e)}')


class Mutation(graphene.ObjectType):
    login = Login.Field()
    refresh_token = RefreshToken.Field()


schema = graphene.Schema(query=Query, mutation=Mutation)
