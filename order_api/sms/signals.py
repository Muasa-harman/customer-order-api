import os
import africastalking
from django.db.models.signals import post_save
from django.dispatch import receiver
from order_api.models import Order


class SMSService:
    def __init__(self):
        if not hasattr(africastalking, '_initialized'):
            africastalking.initialize(
                username='sandbox',
                api_key=os.getenv('AT_API_KEY')
            )
            africastalking._initialized = True
        self.sms = africastalking.SMS

    def send_sms(self, phone, message):
        try:
            response = self.sms.send(message, [phone])
            return response
        except Exception as e:
            print(f"SMS failed: {str(e)}")
            return None

sms_service = SMSService()

@receiver(post_save, sender=Order)
def order_created_handler(sender, instance, created, **kwargs):
    if instance.status == 'confirmed' and instance.customer.phone:
        message = (
            f"Hi {instance.customer.name}, "
            f"your order for {instance.item} (KES {instance.amount}) has been received!"
        )
        sms_service.send_sms(str(instance.customer.phone), message)