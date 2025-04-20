from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
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


class Order(models.Model):
    STATUS_CHOICES = [
        ('NEW', 'new'),
        ('PROCESSING', 'Processing'),
        ('DELIVERED', 'delivered'),
        ('CANCELLED', 'Cancelled'),
    ]

    customer_id = models.UUIDField(max_length=4000, null=False)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='NEW')
    order_details = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.UUIDField(max_length=4000, null=False, default=customer_id)

    class Meta:
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
            models.Index(fields=['customer_id', 'status']),
        ]
