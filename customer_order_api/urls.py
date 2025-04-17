
from django.urls import path
from graphene_django.views import GraphQLView
from django.views.decorators.csrf import csrf_exempt
from mozilla_django_oidc import views as oidc_views

# Correct import for schema
from customer_order_api.schema import schema  # Import from schema.py directly

urlpatterns = [
    # GraphQL Endpoint (primary)
    path('graphql/', csrf_exempt(GraphQLView.as_view(
        graphiql=True,
        schema=schema  
    ))),

    # OIDC Authentication
    path('oidc/login/', oidc_views.OIDCAuthenticationRequestView.as_view(), name='oidc_login'),
    path('oidc/callback/', oidc_views.OIDCAuthenticationCallbackView.as_view(), name='oidc_callback'),
    path('oidc/logout/', oidc_views.OIDCLogoutView.as_view(), name='oidc_logout'),
]