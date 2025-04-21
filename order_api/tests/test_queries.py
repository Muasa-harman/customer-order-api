from django.test import RequestFactory
import pytest
from graphene.test import Client
from customer_order_api.schema import schema
from order_api.models import Orders
from uuid import uuid4
from unittest.mock import patch
from django.utils import timezone

@pytest.mark.django_db
@patch("order_api.schemas.orders_schema.load_keycloak_user_info") 
def test_my_orders_query(mock_user_info):
    user_id = str(uuid4())
    mock_user_info.return_value = {'sub': str(user_id)}

    Orders.objects.create(
        id=uuid4(),
        customer_id=user_id,
        total_price=500.0,
        status="NEW",
        order_details="Deliver ASAP",
        created_by=user_id,
        created_at=timezone.now(),
        updated_at=timezone.now(),
    )

    query = '''
        query {
          myOrders {
            id
            status
            orderDetails
          }
        }
    '''
    factory = RequestFactory()
    request = factory.get('/graphql')
    request.META['HTTP_AUTHORIZATION'] = 'Bearer token'

    client = Client(schema)
    executed = client.execute(
        query,
        context_value=request
    )
    print("\nResponse:", executed)
  
    assert executed["data"]["myOrders"] is not None
    assert len(executed["data"]["myOrders"]) == 1
    assert executed["data"]["myOrders"][0]["status"] == "NEW"
