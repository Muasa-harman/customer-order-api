import pytest
from graphene.test import Client
from unittest.mock import patch
from django.test import RequestFactory
from customer_order_api.schema import schema



@pytest.mark.django_db
@patch("order_api.schemas.orders_schema.load_keycloak_user_info") 
def test_create_order_mutation(mock_user_info):
    user_id = "c0f86a71-d35a-43f0-93c0-2802f88eaf9d"
    mock_user_info.return_value = {'sub': user_id}
    factory = RequestFactory()
    request = factory.post('/graphql')
    request.META['HTTP_AUTHORIZATION'] = 'Bearer valid_token'

    mutation = '''
        mutation {
          createOrder(input: {
            userId: "%s",
            price: 1200.0,
            orderDetails: "Deliver ASAP"
          }) {
            success
            message
            order {
              id
              status
              orderDetails
            }
          }
        }
    ''' % user_id

    # Execute query
    client = Client(schema)
    executed = client.execute(
        mutation,
        context_value=request
    )

    # Verify response
    print("\nMutation Response:", executed)
    
    assert executed["data"]["createOrder"]["success"] is True
    assert executed["data"]["createOrder"]["order"]["status"] == "NEW"


# from types import SimpleNamespace
# from django.test import RequestFactory
# import pytest
# from graphene.test import Client
# from unittest.mock import patch
# # from customer_order_api.schema import schema
# from customer_order_api.schema import schema as schema_instance


# @pytest.mark.django_db
# @patch("order_api.utils.load_keycloak_user_info")
# def test_create_order_mutation(mock_user_info, client):
#     mock_user_info.return_value = {'sub': 'c0f86a71-d35a-43f0-93c0-2802f88eaf9d'}

#     mutation = '''
#         mutation {
#           createOrder(input: {
#             userId: "c0f86a71-d35a-43f0-93c0-2802f88eaf9d",
#             price: 1200.0,
#             orderDetails: "Deliver ASAP"
#           }) {
#             success
#             message
#             order {
#               id
#               status
#               orderDetails
#             }
#           }
#         }
#     '''
#     factory = RequestFactory()
#     request = factory.get('/graphql')
#     request.META['HTTP_AUTHORIZATION'] = 'Bearer token'


#     # client = Client(schema)
#     client = Client(schema_instance)
#     executed = client.execute(
#         mutation,
#         context_value=request,
        
#     )
    
#     print("\n\nMutation Response:", executed)
#     factory = RequestFactory()
#     request = factory.get('/graphql')
#     request.META['HTTP_AUTHORIZATION'] = 'Bearer token'
    
#     mock_context = SimpleNamespace(headers={"Authorization": "Bearer token"})
#     # client = Client(schema_instance=schema, context_value=mock_context)
#     executed = client.execute(mutation, context_value=request)

#     assert executed["data"]["createOrder"]["success"] is True
#     assert executed["data"]["createOrder"]["order"]["status"] == "NEW"
