# myproject/schema.py

import graphene

import order_api.schemas.orders_schema as orders
import order_api.schemas.users_schema as users


class Query(orders.schema.Query, users.schema.Query, graphene.ObjectType):
    pass


schema = graphene.Schema(query=Query)
