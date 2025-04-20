import os
import jwt
import requests
import graphene
from graphql import GraphQLError
from keycloak import KeycloakOpenID
from django.db import transaction
import jwt
from jwt.algorithms import RSAAlgorithm

from order_api.models import Customer, Order, OrderItem

# --------------------------
# GraphQL Types
# --------------------------
class CustomerType(graphene.ObjectType):
    userId = graphene.String()
    code = graphene.String()
    name = graphene.String()
    email = graphene.String()


class OrderItemType(graphene.ObjectType):
    product_id = graphene.String()
    quantity = graphene.Int()
    price = graphene.Float()
    total = graphene.Float()


class OrderType(graphene.ObjectType):
    id = graphene.ID()
    customer = graphene.Field(CustomerType)
    status = graphene.String()
    created_at = graphene.DateTime()
    total_price = graphene.Float()
    items = graphene.List(OrderItemType)

    def resolve_items(self, info):
        return self.items.all()


# --------------------------
# Input Types
# --------------------------
class OrderItemInput(graphene.InputObjectType):
    order_details=graphene.String()
    ordered_by=graphene.String(required=True)
    price = graphene.Float(required=True)
    userId = graphene.String(required=True)
    


class CreateOrder(graphene.Mutation):
    class Arguments:
        input = OrderItemInput(required=True)

    order = graphene.Field(OrderType)
    success = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info, input):
        print("Processing order with details:", input)
        auth_header = info.context.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return CreateOrder(
                order=None,
                success=False,
                message="Missing authorization header",
                errors=["Authorization header missing or invalid"]
            )

        try:
            access_token = auth_header.split(' ')[1]
            print(f"Access Token: {access_token}")
            
            # Get unverified header to find kid
            unverified_header = jwt.get_unverified_header(access_token)
            kid = unverified_header.get("kid")
            
            if not kid:
                return CreateOrder(
                    order=None,
                    success=False,
                    message="Invalid token format",
                    errors=["Token missing key ID (kid) in header"]
                )

            # Fetch JWKS from Keycloak
            realm_url = f"{os.getenv('KEYCLOAK_SERVER_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}"
            jwks_response = requests.get(f"{realm_url}/protocol/openid-connect/certs")
            jwks_response.raise_for_status()
            jwks = jwks_response.json()

            # Find matching key
            signing_key = None
            for key in jwks["keys"]:
                if key["kid"] == kid:
                    signing_key = RSAAlgorithm.from_jwk(key)
                    break

            if not signing_key:
                return CreateOrder(
                    order=None,
                    success=False,
                    message="Invalid token",
                    errors=["No matching signing key found"]
                )

            # Verify token
            decoded_token = jwt.decode(
                access_token,
                key=signing_key,
                algorithms=["RS256"],
                audience=os.getenv("OIDC_CLIENT_ID"),
                issuer=realm_url
            )

           

            # Create order logic
            with transaction.atomic():
                order = Order.objects.create(customer=input.userId, status='PENDING',
                                             created)
            

            return CreateOrder(
                order=order,
                success=True,
                message="Order created successfully",
                errors=[]
            )

        except Customer.DoesNotExist:
            return CreateOrder(
                order=None,
                success=False,
                message="Customer not found",
                errors=["No customer linked to this account"]
            )
        except Exception as e:
            return CreateOrder(
                order=None,
                success=False,
                message="Order creation failed",
                errors=[str(e)]
            )
   

class ConfirmOrder(graphene.Mutation):
    class Arguments:
        order_id = graphene.ID(required=True)

    order = graphene.Field(OrderType)
    success = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info, order_id):
        try:
            auth_header = info.context.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                raise GraphQLError("Missing authorization token")

            realm_url = f"{os.getenv('KEYCLOAK_SERVER_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}"
            jwks = requests.get(f"{realm_url}/protocol/openid-connect/certs").json()
            token = auth_header.split(' ')[1]

            decoded_token = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=os.getenv('OIDC_CLIENT_ID'),
                issuer=realm_url
            )

            customer = Customer.objects.get(oidc_id=decoded_token['sub'])
            order = Order.objects.get(id=order_id, customer=customer)

            if order.status != 'PENDING':
                raise GraphQLError("Only pending orders can be confirmed")

            order.status = 'CONFIRMED'
            order.save()
            
            ConfirmOrder.send_sms_notification(order)

            return ConfirmOrder(
                order=order,
                success=True,
                message="Order confirmed!",
                errors=[]
            )

        except Order.DoesNotExist:
            return ConfirmOrder(
                order=None,
                success=False,
                message="Order not found or already confirmed.",
                errors=["Order not found."]
            )
        except Exception as e:
            return ConfirmOrder(
                order=None,
                success=False,
                message="Failed to confirm order.",
                errors=[str(e)]
            )
        
    @staticmethod
    def send_sms_notification(order):
        customer = order.customer
        message = f"Hi {customer.name}, your order #{order.id} has been confirmed."

        # Example print — replace with SMS gateway integration
        print(f"Sending SMS to {customer.phone_number}: {message}")
        # You could use Twilio, Africa's Talking, etc. here    


# --------------------------
# Queries
# --------------------------
class OrderQuery(graphene.ObjectType):
    my_orders = graphene.List(
        OrderType,
        status=graphene.String(),
    )

    def resolve_my_orders(self, info, status=None):
        auth_header = info.context.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return []

        try:
            realm_url = f"{os.getenv('KEYCLOAK_SERVER_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}"
            jwks = requests.get(f"{realm_url}/protocol/openid-connect/certs").json()
            token = auth_header.split(' ')[1]

            decoded_token = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=os.getenv('OIDC_CLIENT_ID'),
                issuer=realm_url
            )

            customer = Customer.objects.get(oidc_id=decoded_token['sub'])
            queryset = Order.objects.filter(customer=customer)

            if status:
                queryset = queryset.filter(status=status.upper())

            return queryset.order_by('-created_at')

        except Exception as e:
            print(f"Error resolving orders: {str(e)}")
            return []


# --------------------------
# Schema Configuration
# --------------------------
class OrderMutation(graphene.ObjectType):
    create_order = CreateOrder.Field()
    confirm_order = ConfirmOrder.Field()


schema = graphene.Schema(
    query=OrderMutation,
    mutation=OrderMutation,
    auto_camelcase=False
)






# import graphene
# import jwt
# from graphene_django import DjangoObjectType
#
# from order_api.models import Order
#
#
# class OrderType(DjangoObjectType):
#     class Meta:
#         model = Order
#         fields = ("id", "customer", "item", "amount", "time", "status", "quantity")
#
#
# class OrderInput(graphene.InputObjectType):
#     customer_code = graphene.String(required=True)
#     item = graphene.String(required=True)
#     quantity = graphene.Int(required=True)
#     unit_price = graphene.Float(required=True)


# class CreateOrder(graphene.Mutation):
#     class Arguments:
#         input = OrderInput(required=True)

#     order = graphene.Field(OrderType)
#     success = graphene.Boolean()
#     message = graphene.String()
#     errors = graphene.List(graphene.String)

#     @classmethod
#     def mutate(cls, root, info, input):
#         try:
#             auth_header = info.context.headers.get('Authorization')
#             if not auth_header or not auth_header.startswith('Bearer '):
#                 raise GraphQLError("You are not Authorized to make order login first")

#             token = auth_header.split(' ')[1]

#             # Validate the token
#             try:
#                 decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
#             except jwt.ExpiredSignatureError:
#                 raise GraphQLError("Token has expired.")
#             except jwt.InvalidTokenError:
#                 raise GraphQLError("Invalid token.")

#             user_id = decoded_token.get('user_id')  # Adjust based on your token payload
#             if not user_id:
#                 raise GraphQLError("Invalid token payload: {user_id} is missing.")

#             # Optionally, check user roles or permissions
#             roles = decoded_token.get('roles', [])
#             if 'customer' not in roles and 'admin' not in roles:
#                 raise GraphQLError("You do not have permission to create an order.")

#             # Proceed with order creation
#             if input.quantity < 1:
#                 raise ValidationError('Quantity must be at least 1.')

#             if not input.item.strip():
#                 raise ValidationError("Item cannot be empty.")

#             if input.unit_price <= 0:
#                 raise ValidationError("Price must be greater than 0.")


#             customer = Customer.objects.get(code=input.customer_code)
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
#                 message="Order created!",
#                 errors=[]
#             )

#         except Customer.DoesNotExist:
#             return CreateOrder(
#                 order=None,
#                 success=False,
#                 message="Customer not found.",
#                 errors=["Customer does not exist."]
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
#             )


