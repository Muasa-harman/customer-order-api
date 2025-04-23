import json
import os
import traceback
import uuid
import graphene
from graphql import GraphQLError
from django.utils import timezone 

from order_api.models import  Orders
from order_api.utils.load_keycloak_user_info import load_keycloak_user_info
from order_api.utils.order_helpers import parse_order_details


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
                    created_at=timezone.now(),
                    updated_at=timezone.now()
                )

                return CreateOrder(
                    order=order,
                    success=True,
                    message="Order created successfully!",
                    errors=[]
                )

        except Exception as e:
            import  traceback
            print("Error creating order:", e)
            traceback.print_exc()
            return CreateOrder(
                order=None,
                success=False,
                message="Failed to create order.",
                errors=[str(e)]
            )


# class ConfirmOrder(graphene.Mutation):
#     class Arguments:
#            order_id = graphene.String(required=True)

#     order = graphene.Field(OrderType)
#     success = graphene.Boolean()
#     message = graphene.String()
#     errors = graphene.List(graphene.String)

#     @staticmethod
#     def mutate(root, info, order_id):
#         try:
#             # update_order_id = order_id.strip()
#             # uuid.UUID(order_id.strip(), version=4)
#             try:
#                 uuid.UUID(order_id.strip(), version=4)
#             except ValueError:
#                 raise ValueError("Invalid UUID format")
               
#             auth_header = info.context.headers.get('Authorization')
#             if not auth_header or not auth_header.startswith('Bearer '):
#                 raise GraphQLError("Missing authorization token")

#             user_info = load_keycloak_user_info(auth_header)
#             try:
#                 order = Orders.objects.get(id=order_id)
#             except Orders.DoesNotExist:
#                 raise GraphQLError("Order not found")
        
#             if order.status != 'NEW':
#                 raise GraphQLError("Only new orders can be confirmed")
            
        
#             order_data = parse_order_details(order.order_details)
#             if 'error' in order_data:
#                 raise ValueError(order_data["error"])

#             order.status = 'CONFIRMED'
#             order._user_info = user_info
#             order.save()
             
           
          
#             ConfirmOrder.send_confirmation_sms(order,user_info,order_data)

#             return ConfirmOrder(
#                 order=order,
#                 success=True,
#                 message="Order confirmed!",
#                 errors=[]
#             )

#         except Orders.DoesNotExist:
#             return ConfirmOrder(
#                 order=None,
#                 success=False,
#                 message="Order not found or already confirmed.",
#                 errors=["Order not found."]
#             )
#         except Exception as e:
#             return ConfirmOrder(
#                 order=None,
#                 success=False,
#                 message="Failed to confirm order.",
#                 errors=[str(e)]
    
        # )
# class ConfirmOrder(graphene.Mutation):
#     class Arguments:
#         order_id = graphene.String(required=True)

#     order = graphene.Field(OrderType)
#     success = graphene.Boolean()
#     message = graphene.String()
#     errors = graphene.List(graphene.String)



#     @staticmethod
#     def mutate(root, info, order_id):
#         try:
#             # Validate UUID format
#             try:
#                 uuid.UUID(order_id.strip(), version=4)
#             except ValueError:
#                 raise ValueError("Invalid UUID format")

#             # Validate authorization
#             auth_header = info.context.headers.get('Authorization')
#             if not auth_header or not auth_header.startswith('Bearer '):
#                 raise GraphQLError("Missing authorization token")

#             user_info = load_keycloak_user_info(auth_header)

#             # Fetch the order
#             try:
#                 order = Orders.objects.get(id=order_id)
#             except Orders.DoesNotExist:
#                 raise GraphQLError("Order not found")

#             if order.status != 'NEW':
#                 raise GraphQLError("Only new orders can be confirmed")

#             # Parse order details
#             try:
#                 order_data = parse_order_details(order.order_details)
#             except ValueError as e:
#                 raise GraphQLError(f"Failed to parse order details: {str(e)}")

#             # Update order status
#             order.status = 'CONFIRMED'
#             order._user_info = user_info
#             order.save()

#             # Trigger SMS notification
#             ConfirmOrder.send_confirmation_sms(order, user_info, order_data)

#             return ConfirmOrder(
#                 order=order,
#                 success=True,
#                 message="Order confirmed!",
#                 errors=[]
#             )

#         except Exception as e:
#             return ConfirmOrder(
#                 order=None,
#                 success=False,
#                 message="Failed to confirm order.",
#                 errors=[str(e)]
#             )        
#     @staticmethod
#     def send_confirmation_sms(order, user_info, order_data):
#         """
#         Sends an SMS notification to the customer when the order is confirmed.
#         """
#         try:
#             # Extract phone number from order details or user info
#             phone_number = order_data.get('phone_number') or user_info.get('phone')
#             if not phone_number:
#                 raise ValueError("Phone number not found")

#             # Format the phone number
#             if not phone_number.startswith('+'):
#                 phone_number = f"+{phone_number.lstrip('0')}"

#             # Construct the SMS message
#             message = (
#                 f"Hi {user_info.get('full_name', 'Customer')}, your order has been confirmed!\n"
#                 f"Items: {order_data.get('item', 'N/A')}\n"
#                 f"Total: KES {order_data.get('amount', 0)}\n"
#                 f"Thank you for choosing {os.getenv('COMPANY_NAME', 'Our Store')}!"
#             )
#              # Send the SMS using Africa's Talking
#             from order_api.sms.signals import SMSService
#             sms_service = SMSService()
#             response = sms_service.send_order_sms(phone_number, user_info, order_data)

#             if response:
#                 print(f"SMS sent successfully to {phone_number}")
#             else:
#                 print(f"Failed to send SMS to {phone_number}")

#         except Exception as e:
#             print(f"Error sending SMS: {str(e)}")   
#     # @staticmethod
#     # def send_confirmation_email( user_info, order):
#     # #   email/sms notification logic here
#         # print(f"Order {order.id} confirmed! Notification sent to {user_info.o}")

#     @staticmethod
#     def send_confirmation_sms( order,user_info, order_data):
#     # #   email/sms notification logic here
#         print(f"Order {order.id} confirmed! Notification sent to {order_data['phone_number']}")

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
            # Validate UUID format
            try:
                uuid.UUID(order_id.strip(), version=4)
            except ValueError:
                raise ValueError("Invalid UUID format")

            # Validate authorization
            auth_header = info.context.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                raise GraphQLError("Missing authorization token")

            # Load user info from Keycloak
            user_info = load_keycloak_user_info(auth_header)

            # Fetch the order
            try:
                order = Orders.objects.get(id=order_id)
            except Orders.DoesNotExist:
                raise GraphQLError("Order not found")

            if order.status != 'NEW':
                raise GraphQLError("Only new orders can be confirmed")

            # Update order status
            order.status = 'CONFIRMED'
            order._user_info = user_info
            order.save()

            # Trigger SMS notification
            ConfirmOrder.send_confirmation_sms(order, user_info)

            return ConfirmOrder(
                order=order,
                success=True,
                message="Order confirmed!",
                errors=[]
            )

        except Exception as e:
            return ConfirmOrder(
                order=None,
                success=False,
                message="Failed to confirm order.",
                errors=[str(e)]
            )

    @staticmethod
    def send_confirmation_sms(order, user_info):
        """
        Sends an SMS notification to the customer when the order is confirmed.
        """
        try:
            # Extract phone number from user info
            phone_number = user_info.get('phone_number', '')
            if not phone_number:
                raise ValueError("Phone number not found")

            # Format the phone number
            if not phone_number.startswith('+'):
                phone_number = f"+{phone_number.lstrip('0')}"

            # Construct the SMS message
            message = (
                f"Hi {user_info.get('full_name', 'Customer')}, your order {order.id} has been confirmed!\n"
                f"Details: {order.order_details}\n"
                f"Total: KES {order.total_price}\n"
                f"Thank you for choosing {os.getenv('COMPANY_NAME', 'Our Store')}!"
            )

            # Send the SMS using Africa's Talking
            from order_api.sms.signals import SMSService
            sms_service = SMSService()
            response = sms_service.send_order_sms(phone_number, message)

            if response:
                print(f"SMS sent successfully to {phone_number}")
            else:
                print(f"Failed to send SMS to {phone_number}")

        except Exception as e:
            print(f"Error sending SMS: {str(e)}")


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
