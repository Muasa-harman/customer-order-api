import graphene
from order_api.schemas.customer_schema import CustomerQuery, CustomerMutation
from order_api.schemas.orders_schema import OrderQuery,OrderMutation
from order_api.schemas.users_schema import AuthQuery, AuthMutation

class Query(CustomerQuery, OrderQuery, AuthQuery, graphene.ObjectType):
    pass

class Mutation(CustomerMutation, OrderMutation, AuthMutation, graphene.ObjectType):
    pass


schema = graphene.Schema(query=Query, mutation=Mutation)

