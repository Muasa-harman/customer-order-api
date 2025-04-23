import os
import africastalking
from django.db.models.signals import post_save
from django.dispatch import receiver
from order_api.models import Orders

class SMSService:
    def __init__(self):
        if not hasattr(africastalking, '_initialized'):
            africastalking.initialize(
                username=os.getenv('AT_USERNAME', 'sandbox'),
                api_key=os.getenv('AT_API_KEY')
            )
            africastalking._initialized = True
        self.sms = africastalking.SMS

    def send_order_sms(self, phone, message):
        try:
            # Format phone number
            if not phone.startswith('+'):
                phone = f"+{phone.lstrip('0')}"

            # Send SMS
            response = self.sms.send(message, [phone])
            return response['SMSMessageData']['Recipients'][0]['status'] == 'Success'
        except Exception as e:
            print(f"SMS sending failed: {str(e)}")
            return False
print("AT_USERNAME:", os.getenv('AT_USERNAME'))
print("AT_API_KEY:", os.getenv('AT_API_KEY'))

sms_service = SMSService()

@receiver(post_save, sender=Orders)
def order_created_handler(sender, instance, created, **kwargs):
    if instance.status.lower() == 'confirmed' and instance.order_details:
        user_info = getattr(instance, 'user_info', None) or {}
        phone_number = user_info.get('phone', '')

        if not phone_number:
            print('Phone number not found. Skipping SMS')
            return

        message = (
            f"Hi {user_info.get('full_name', 'Customer')}, your order {instance.id} has been confirmed!\n"
            f"Details: {instance.order_details}\n"
            f"Total: KES {instance.total_price}\n"
            f"Thank you for choosing {os.getenv('COMPANY_NAME', 'Our Store')}!"
        )

        # Send SMS
        response = sms_service.send_order_sms(phone=phone_number, message=message)
        if response:
            print(f"SMS sent successfully to {phone_number}")
        else:
            print(f"Failed to send SMS to {phone_number}")


