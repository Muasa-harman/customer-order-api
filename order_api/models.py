from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator, MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _


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


class Customer(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        _('email address'),
        unique=True,
        error_messages={
            'unique': _('A customer with this email already exists.'),
        }
    )
    name = models.CharField(
        max_length=100,
        validators=[RegexValidator(r'^[a-zA-Z ]+$', 'Only letters and spaces allowed')]
    )
    code = models.CharField(
        max_length=20,
        unique=True,
        validators=[RegexValidator(r'^CUST-\d{4}$', 'Code must be in format CUST-0000')]
    )
    phone = models.CharField(
        max_length=17,
        blank=True,
        validators=[RegexValidator(r'^\+?1?\d{9,15}$', 'Phone number must be in format: "+999999999"')]
    )
    oidc_id = models.CharField(
        max_length=255,
        unique=True,
        null=True,
        blank=True,
        help_text=_('OpenID Connect user identifier')
    )
    roles = models.JSONField(
        default=list,
        help_text=_('List of user roles')
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
    )
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
    )
    date_joined = models.DateTimeField(_('date joined'), auto_now_add=True)
    last_login = models.DateTimeField(_('last login'), null=True, blank=True)

    # Add related_name to avoid clashes
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name=_('groups'),
        blank=True,
        related_name='customer_set',
        related_query_name='customer'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name=_('user permissions'),
        blank=True,
        related_name='customer_set',
        related_query_name='customer'
    )

    objects = CustomerManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'code']

    class Meta:
        verbose_name = _('customer')
        verbose_name_plural = _('customers')
        ordering = ['name']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['code']),
            models.Index(fields=['oidc_id']),
            models.Index(fields=['phone']),
        ]

    def __str__(self):
        return f"{self.name} ({self.code})"

    @property
    def is_admin(self):
        return 'admin' in self.roles

    @property
    def is_customer(self):
        return 'customer' in self.roles


class Order(models.Model):
    STATUS_CHOICES = [
        ('NEW', 'new'),
        ('PROCESSING', 'Processing'),
        ('DELIVERED', 'delivered'),
        ('CANCELLED', 'Cancelled'),
    ]

    customer_id= models.UUIDField( max_length=4000,null=False)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='NEW')
    order_details = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by=models.UUIDField( max_length=4000,null=False,default=customer_id)

    class Meta:
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
            models.Index(fields=['customer', 'status']),
        ]