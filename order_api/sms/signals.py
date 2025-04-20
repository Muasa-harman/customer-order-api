import os
import africastalking
from django.db.models.signals import post_save
from django.dispatch import receiver
from order_api.models import  Orders


class SMSService:
    def __init__(self):
        if not hasattr(africastalking, '_initialized'):
            africastalking.initialize(
                username=('AT_USERNAME','sandbox'),
                api_key=os.getenv('AT_API_KEY')
            )
            africastalking._initialized = True
        self.sms = africastalking.SMS

    def send_order_sms(self, phone, message,user_info,order_details):
        try:
            f"Hi {user_info}, your order has been confirmed!\n"
            f"Items: {order_details['item']}\n"
            f"Total: KES {order_details['amount']}\n"
            f"Thank you for choosing {os.getenv('COMPANY_NAME', 'Our Store')}!"

            if not phone.startswith('+'):
                phone = f"+{phone.lstrip('0')}"

            response = self.sms.send(message, [phone])

            return response['SMSMessageData']['Recipients'][0]['status'] == 'Success'
        except Exception as e:
            print(f"SMS sending failed: {str(e)}")
            return False


sms_service = SMSService()


@receiver(post_save, sender=Orders)
def order_created_handler(sender, instance, created, **kwargs):
    if instance.status == 'confirmed' and instance.phone_number:
        sms_service.send_order_sms(
                phone=instance.phone_number,
                customer_name=instance.name,
                order_details={
                    'item': instance.item,
                    'amount': instance.amount
                }
            )
      
