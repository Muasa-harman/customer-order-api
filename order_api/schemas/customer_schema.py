import graphene
from graphene_django import DjangoObjectType
from django.core.exceptions import ValidationError

from order_api.models import Customer



class CustomerType(DjangoObjectType):
    class Meta:
        model = Customer
        fields = ("id", "name", "code", "phone")

class CustomerInput(graphene.InputObjectType):
    name = graphene.String(required=True)
    code = graphene.String(required=True)
    phone = graphene.String()       

class CreateCustomer(graphene.Mutation):
    class Arguments:
       input = CustomerInput(required=True)

    customer = graphene.Field(CustomerType)
    success = graphene.Boolean()
    errors =  graphene.List(graphene.String)
    message= graphene.String()


    @classmethod
    def mutate(cls, root, info, input):
        try:
            name = input.name.strip() if input.name else ""
            code = input.code.strip() if input.code else ""
            phone = input.phone.strip() if input.phone else ""

            if not name:
                raise ValidationError("Name is required.")
            if not code:
                raise ValidationError("Code is required.")
            if Customer.objects.filter(code=code).exists():
                raise ValidationError("Customer code already exists.")
            
            customer = Customer(name=name, code=code, phone=phone)
            customer.full_clean() 
            customer.save()

            return CreateCustomer(
                customer=customer,
                success=True,
                message="Customer created successfully!",
                errors=[]
            )

        except ValidationError as e:
            return CreateCustomer(
                customer=None,
                success=False,
                message="Failed to create customer.",
                errors=e.messages
            )

    
class CustomerQuery(graphene.ObjectType):
    all_customers = graphene.List(CustomerType)
    customer_by_code = graphene.Field(CustomerType, code=graphene.String(required=True))

    def resolve_all_customers(root, info):
        return Customer.objects.all()

    def resolve_customer_by_code(root, info, code):
        return Customer.objects.get(code=code)


class CustomerMutation(graphene.ObjectType):
    create_customer = CreateCustomer.Field()  