import uuid
import graphene
from graphql import GraphQLError
from datetime import datetime as Datetime

from order_api.models import  Orders
from order_api.utils.load_keycloak_user_info import load_keycloak_user_info


# --------------------------
# GraphQL Types
# --------------------------
class OrderItemType(graphene.ObjectType):
    product_id = graphene.String()
    quantity = graphene.Int()
    price = graphene.Float()
    total = graphene.Float()


class OrderType(graphene.ObjectType):
    id = graphene.ID()
    customer_id = graphene.String()
    status = graphene.String()
    created_at = graphene.DateTime()
    total_price = graphene.Float()
    order_details = graphene.String()
    created_by = graphene.String()


# --------------------------
# Input Types
# --------------------------
class OrderItemInput(graphene.InputObjectType):
    order_details = graphene.String()
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
        try:
            auth_header = info.context.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                raise GraphQLError("Missing authorization token")

            user_info = load_keycloak_user_info(auth_header)
            if user_info is not None:
                order = Orders.objects.create(
                    customer_id=input.userId,
                    total_price=input.price,
                    status='NEW',
                    order_details=input.order_details,
                    created_by=user_info['sub'],
                    created_at=Datetime.now(),
                    updated_at=Datetime.now()
                )

                return CreateOrder(
                    order=order,
                    success=True,
                    message="Order created successfully!",
                    errors=[]
                )

        except Exception as e:
            return CreateOrder(
                order=None,
                success=False,
                message="Failed to create order.",
                errors=[str(e)]
            )


class ConfirmOrder(graphene.Mutation):
    class Arguments:
           order_id = graphene.String(required=True)

    order = graphene.Field(OrderType)
    success = graphene.Boolean()
    message = graphene.String()
    errors = graphene.List(graphene.String)

    @staticmethod
    def mutate(root, info, order_id):
        try:
            update_order_id = order_id.strip()
            uuid.UUID(update_order_id, version=4)
            try:
                uuid.UUID(update_order_id, version=4)
            except ValueError:
                raise ValueError("Invalid UUID format")
               
            auth_header = info.context.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                raise GraphQLError("Missing authorization token")

            user_info = load_keycloak_user_info(auth_header)
            print(f"User info: {user_info}")
            order = Orders.objects.get(id=order_id)

            if order.status != 'NEW':
                raise GraphQLError("Only pending orders can be confirmed")

            order.status = 'CONFIRMED'
            order.save()

            ConfirmOrder.send_confirmation_email(order)
            ConfirmOrder.send_confirmation_sms(order)

            # Simplified notification without customer details
            print(f"Order #{order.id} has been confirmed for customer ID: {order.customer_id}")

            return ConfirmOrder(
                order=order,
                success=True,
                message="Order confirmed!",
                errors=[]
            )

        except Orders.DoesNotExist:
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
    def send_confirmation_email( order):
    #   email/sms notification logic here
        print(f"Order {order.id} confirmed! Notification sent to {order.customer.email}")

    @staticmethod
    def send_confirmation_sms( order):
    #   email/sms notification logic here
        print(f"Order {order.id} confirmed! Notification sent to {order.customer.phone}")



class OrderQuery(graphene.ObjectType):
    my_orders = graphene.List(
        OrderType,
        status=graphene.String(),
    )

    def resolve_my_orders(self, info, status=None):
        try:
            auth_header = info.context.headers.get('Authorization')
            if not auth_header:
                raise GraphQLError("Authentication required")

            user_info = load_keycloak_user_info(auth_header)
            queryset = Orders.objects.filter(customer_id=user_info['sub'])

            if status:
                queryset = queryset.filter(status=status.upper())

            return queryset.order_by('-created_at')

        except Exception as e:
            raise GraphQLError(f"Failed to fetch orders: {str(e)}")



class OrderMutation(graphene.ObjectType):
    create_order = CreateOrder.Field()
    confirm_order = ConfirmOrder.Field()


schema = graphene.Schema(
    query=OrderQuery,
    mutation=OrderMutation,
    auto_camelcase=False
)
