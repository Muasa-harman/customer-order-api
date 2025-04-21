import uuid
from django.contrib.auth.models import  BaseUserManager
from django.db import models


class CustomerManager(BaseUserManager):
    def create_user(self, email, name, code, password=None, **extra_fields):
        if not email:
            raise ValueError('Email address is required')
        if not name:
            raise ValueError('Name is required')
        if not code:
            raise ValueError('Customer code is required')

        email = self.normalize_email(email)
        user = self.model(
            email=email,
            name=name,
            code=code,
            **extra_fields
        )

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, code, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('roles', ['admin'])

        return self.create_user(email, name, code, password, **extra_fields)


class Orders(models.Model):
    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('CONFIRMED', 'Confirmed'),
    ]
    
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    customer_id = models.UUIDField()
    total_price = models.FloatField(blank=True, null=True)
    status = models.CharField(max_length=20)
    order_details = models.TextField()
    # order_details = models.CharField()
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)
    created_by = models.UUIDField()

    class Meta:
        db_table = 'orders'

    def __str__(self):
       return f"Order {self.id}"    
