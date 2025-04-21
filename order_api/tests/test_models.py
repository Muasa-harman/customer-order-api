import pytest
from order_api.models import Orders
from uuid import uuid4
from django.utils import timezone

@pytest.mark.django_db(transaction=True)
def test_order_model_creation():
    order = Orders.objects.create(
        id=uuid4(),
        customer_id=uuid4(),
        total_price=99.99,
        status='NEW',
        order_details='Please handle with care',
        created_at=timezone.now(),
        updated_at=timezone.now(),
        created_by=uuid4()
    )

    assert Orders.objects.count() == 1
    assert order.status == 'NEW'
    assert str(order) == f"Order {order.id}" 
