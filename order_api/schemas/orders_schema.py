import graphene
from graphene_django import DjangoObjectType
from django.core.exceptions import ValidationError
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
            if input.quantity < 1:
                raise ValidationError('Quantity must be at least 1.')

            if not input.item.strip():
                raise ValidationError("Item cannot be empty.")

            if input.unit_price <= 0:
                raise ValidationError("Price must be greater than 0.")

            customer = Customer.objects.get(code=input.customer_code)
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
                message="Order created!",
                errors=[]
            )

        except Customer.DoesNotExist:
            return CreateOrder(
                order=None,
                success=False,
                message="Customer not found.",
                errors=["Customer does not exist."]
            )
        except ValidationError as e:
            return CreateOrder(
                order=None,
                success=False,
                message="Validation failed.",
                errors=e.messages
            )

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
            order = Order.objects.get(id=order_id, status='draft')
            order.status = 'confirmed'
            order.save()
            
            # Call static method for notification
            cls.send_confirmation_email(order)

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
                message="Invalid or already confirmed order.",
                errors=["Order not found."]
            )
    
    @staticmethod
    def send_confirmation_email(order):
        # email/sms notification logic here
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