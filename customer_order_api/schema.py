import graphene

from order_api.schemas.orders_schema import OrderQuery, OrderMutation
from order_api.schemas.users_schema import AuthQuery, AuthMutation


class Query(OrderQuery, AuthQuery, graphene.ObjectType):
    pass


class Mutation(OrderMutation, AuthMutation, graphene.ObjectType):
    pass


schema = graphene.Schema(query=Query, mutation=Mutation)
