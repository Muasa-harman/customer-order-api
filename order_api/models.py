from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator, MinValueValidator
from phonenumber_field.modelfields import PhoneNumberField

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class Customer(models.Model):
    user = models.OneToOneField(
        'CustomUser',
        on_delete=models.CASCADE,
        related_name='customer_profile',
        null=True,
        blank=True
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
    phone = PhoneNumberField(
        region='KE',  
        blank=True,
        null=True,
        help_text="Phone number in international format (+254...)",
        unique=True
    )

    def __str__(self):
        return f"{self.name} ({self.code})"

    class Meta:
        verbose_name = "Customer"
        verbose_name_plural = "Customers"
        ordering = ['name']
        indexes = [
            models.Index(fields=['code']),
            models.Index(fields=['phone']),
        ]

class Order(models.Model):
    STATUS_DRAFT = 'draft'
    STATUS_CONFIRMED = 'confirmed'
    STATUS_CHOICES = [
        (STATUS_DRAFT, 'Draft'),
        (STATUS_CONFIRMED, 'Confirmed'),
    ]

    customer = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE,
        related_name='orders'
    )
    created_by = models.ForeignKey(
        'CustomUser',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_orders'
    )
    item = models.CharField(
        max_length=100,
        validators=[RegexValidator(r'^[a-zA-Z0-9 ]+$', 'Only alphanumeric characters allowed')]
    )
    unit_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        validators=[MinValueValidator(0.01)]
    )
    quantity = models.PositiveIntegerField(
        default=1,
        validators=[MinValueValidator(1)]
    )
    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        editable=False
    )
    time = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default=STATUS_DRAFT
    )

    def save(self, *args, **kwargs):
        self.amount = self.unit_price * self.quantity
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Order #{self.id} - {self.item} ({self.status})"

    class Meta:
        ordering = ['-time']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['-time']),
        ]
        verbose_name = "Order"
        verbose_name_plural = "Orders"

class CustomUser(AbstractUser):
    username = None
    email = models.EmailField(_('email address'), unique=True)
    phone = PhoneNumberField(region='KE', blank=True, null=True)
    oidc_id = models.CharField(
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        help_text="OpenID Connect subject identifier"
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []


    def __str__(self):
        return f"{self.email} ({self.oidc_id or 'local'})"

    @property
    def is_admin(self):
        return 'admin' in self.roles

    @property
    def is_customer(self):
        return 'customer' in self.roles

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")
        indexes = [
            models.Index(fields=['oidc_id']),
            models.Index(fields=['email']),
            # models.Index(fields=['roles'], name='roles_idx'),
        ]
        ordering = ['email']