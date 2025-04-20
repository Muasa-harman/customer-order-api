import pytest
from graphene.test import Client
from unittest.mock import patch

from customer_order_api.schema import schema

@pytest.mark.django_db
@patch("order_api.utils.load_keycloak_user_info")
def test_create_order_mutation(mock_user_info, client):
    mock_user_info.return_value = {'sub': 'c0f86a71-d35a-43f0-93c0-2802f88eaf9d'}

    mutation = '''
        mutation {
          createOrder(input: {
            userId: "c0f86a71-d35a-43f0-93c0-2802f88eaf9d",
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
    '''

    client = Client(schema)
    executed = client.execute(
        mutation,
        context_value={"headers": {"Authorization": "Bearer token"}}
    )
    print("\n\nMutation Response:", executed)

    assert executed["data"]["createOrder"]["success"] is True
    assert executed["data"]["createOrder"]["order"]["status"] == "NEW"
