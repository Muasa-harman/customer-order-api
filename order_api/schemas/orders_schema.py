from django.conf import settings
import graphene
from graphene_django import DjangoObjectType
from django.core.exceptions import ValidationError
from graphql import GraphQLError
import jwt
from order_api.models import Customer, Order

class OrderType(DjangoObjectType):
    class Meta:
        model = Order
        fields = ("id", "customer", "item", "amount", "time", "status", "quantity")

class OrderInput(graphene.InputObjectType):
    customer_code = graphene.String(required=True)
    item = graphene.String(required=True)
    quantity = graphene.Int(required=True)
    unit_price = graphene.Float(required=True)

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


import requests
from jose import jwt
from graphql import GraphQLError
from django.core.exceptions import ValidationError
from order_api.models import Customer, Order
import graphene
import os

class CreateOrder(graphene.Mutation):
    class Arguments:
        input = OrderInput(required=True)

    order = graphene.Field(OrderType)
    success = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, input):
        try:
            # Extract token from Authorization header
            auth_header = info.context.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                raise GraphQLError("Authorization token is missing or invalid.")

            token = auth_header.split(' ')[1]

            # Fetch Keycloak public key dynamically
            realm_url = f"{os.getenv('KEYCLOAK_SERVER_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}"
            certs_url = f"{realm_url}/protocol/openid-connect/certs"
            certs_response = requests.get(certs_url)
            certs_response.raise_for_status()
            jwks = certs_response.json()

            # Decode & verify the token using jose.jwt
            decoded_token = jwt.decode(
                token,
                jwks,
                algorithms=['RS256'],
                audience=os.getenv('OIDC_CLIENT_ID'),
                issuer=f"{realm_url}"
            )

            email = decoded_token.get('email')
            roles = decoded_token.get('realm_access', {}).get('roles', [])

            if not email:
                raise GraphQLError("Email is missing in token.")

            # Ensure the customer exists
            try:
                customer = Customer.objects.get(email=email)
            except Customer.DoesNotExist:
                raise GraphQLError("Customer associated with this token does not exist.")

            # Validate order input
            if input.quantity < 1:
                raise ValidationError('Quantity must be at least 1.')

            if not input.item.strip():
                raise ValidationError("Item cannot be empty.")

            if input.unit_price <= 0:
                raise ValidationError("Price must be greater than 0.")

            # Create the order
            order = Order(
                customer=customer,
                item=input.item,
                quantity=input.quantity,
                unit_price=input.unit_price
            )
            order.full_clean()
            order.save()

            return CreateOrder(
                order=order,
                success=True,
                message="Order created successfully!",
                errors=[]
            )

        except ValidationError as e:
            return CreateOrder(
                order=None,
                success=False,
                message="Validation failed.",
                errors=e.messages
            )
        except Exception as e:
            import traceback
            traceback.print_exc()
            return CreateOrder(
                order=None,
                success=False,
                message="An error occurred.",
                errors=[str(e)]
            )

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
#             )

# class ConfirmOrder(graphene.Mutation):
#     class Arguments:
#         order_id = graphene.ID(required=True)

#     order = graphene.Field(OrderType)
#     success = graphene.Boolean()
#     message = graphene.String()
#     errors = graphene.List(graphene.String)
    
#     @classmethod
#     def mutate(cls, root, info, order_id):
#         try:
#             order = Order.objects.get(id=order_id, status='draft')
#             order.status = 'confirmed'
#             order.save()
            
#             # Call static method for notification
#             cls.send_confirmation_email(order)

#             return ConfirmOrder(
#                 order=order,
#                 success=True,
#                 message="Order confirmed!",
#                 errors=[]
#             )
#         except Order.DoesNotExist:
#             return ConfirmOrder(
#                 order=None,
#                 success=False,
#                 message="Invalid or already confirmed order.",
#                 errors=["Order not found."]
#             )
    
#     @staticmethod
#     def send_confirmation_email(order):
#         # email/sms notification logic here
#         print(f"Order {order.id} confirmed! Notification sent to {order.customer.email}")
import os
import requests
from jose import jwt
from graphql import GraphQLError
from order_api.models import Order 
import graphene

class ConfirmOrder(graphene.Mutation):
    class Arguments:
        order_id = graphene.ID(required=True)

    order = graphene.Field(OrderType)
    success = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @classmethod
    def mutate(cls, root, info, order_id):
        try:
            # Extract token from headers
            auth_header = info.context.headers.get('Authorization')
            print("Authorization Header:", auth_header)

            if not auth_header or not auth_header.startswith('Bearer '):
                raise GraphQLError("Authorization token is missing or invalid.")

            token = auth_header.split(' ')[1]

            # Fetch Keycloak public keys (JWKS)
            realm_url = f"{os.getenv('KEYCLOAK_SERVER_URL')}/realms/{os.getenv('KEYCLOAK_REALM')}"
            certs_url = f"{realm_url}/protocol/openid-connect/certs"
            jwks = requests.get(certs_url).json()

            # Decode & verify the token
            decoded_token = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=os.getenv('OIDC_CLIENT_ID'),
                issuer=realm_url
            )

            roles = decoded_token.get('realm_access', {}).get('roles', [])

            # Check if user has 'admin' role
            if 'admin' not in roles:
                raise GraphQLError("You do not have permission to confirm an order.")

            # Ensure the order exists and is in draft status
            try:
                order = Order.objects.get(id=order_id, status='draft')
            except Order.DoesNotExist:
                raise GraphQLError("Invalid or already confirmed order.")

            # Confirm the order
            order.status = 'confirmed'
            order.save()

            # Send confirmation (email/sms)
            cls.send_confirmation_email(order)

            return ConfirmOrder(
                order=order,
                success=True,
                message="Order confirmed!",
                errors=[]
            )

        except Exception as e:
            import traceback
            traceback.print_exc()
            return ConfirmOrder(
                order=None,
                success=False,
                message="An error occurred.",
                errors=[str(e)]
            )

    @staticmethod
    def send_confirmation_email(order):
        # Placeholder for actual email/SMS logic
        print(f"Order {order.id} confirmed! Notification sent to {order.customer.email}")


class OrderMutation(graphene.ObjectType):
    create_order = CreateOrder.Field()
    confirm_order = ConfirmOrder.Field()

class OrderQuery(graphene.ObjectType):
    all_orders = graphene.List(OrderType)
    orders_by_customer = graphene.List(OrderType, customer_code=graphene.String(required=True))

    def resolve_all_orders(self, info):
        return Order.objects.all()

    def resolve_orders_by_customer(self, info, customer_code):
        customer = Customer.objects.get(code=customer_code)
        return Order.objects.filter(customer=customer)