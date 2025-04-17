from django.apps import AppConfig


class OrderApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'order_api'


class CustomersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'customers'


class OrdersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'orders'

    def ready(self):
        from .sms import signals
        _=signals


class UsersConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'users' 
    verbose_name = "User Authentication"       