# customer-order-service API

[![CI/CD](https://github.com/Muasa-harman/customer-order-service/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/Muasa-harman/customer-order-service/actions)

[![GraphQL](https://img.shields.io/badge/API-GraphQL-e10098.svg)](https://graphql.org/)


A Django-based GraphQL API for managing customers and orders, with OpenID Connect authentication and SMS notifications.

## Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Authentication Flow](#authentication-flow)
- [SMS Integration](#sms-integration)
- [Deployment](#deployment)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Support](#support)

## Project Structure
customer-order-service/
├── customer_order_api/ # Core Django settings
│ ├── settings/ # Environment-specific configs
│ │ ├── base.py
│ │ ├── production.py
│ │ └── development.py
│ ├── urls.py # API endpoints
│ └── asgi.py
├── customers/ 
│ ├── models.py 
│ ├── schema.py 
│ └── tests/
├── orders/ # Order processing
│ ├── models.py # Order data model
│ ├── sms.py # SMS notification handlers
│ └── schema.py
├── docker/ # Docker configurations
│ ├── nginx/
│ └── postgres/
├── .github/ # CI/CD workflows
│ └── workflows/
├── docs/ # Documentation assets
│ ├── ARCHITECTURE.md
│ └── API_REFERENCE.md
├── Dockerfile
├── requirements.txt
└── manage.py

## Features
- Create customers with name, code, and phone number
- Create orders linked to customers
- OpenID Connect authentication via Keycloak
- SMS notifications via Africa's Talking
- Unit tests with 90%+ coverage
- CI/CD with GitHub Actions
- Docker/Kubernetes support

## Installation
```bash
# Clone repository
git clone https://github.com/Muasa-harman/customer-order-api
cd customer-order-service

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

# Set up envi
cp .env.example .env
nano .env  


# .env
DJANGO_SETTINGS_MODULE=customer_order_api.settings
DEBUG=True
SECRET_KEY=
ALLOWED_HOSTS=your-app.onrender.com


# .env
POSTGRES_DB=customer-order-service
POSTGRES_USER=postgres
POSTGRES_PASSWORD=donfiles.online
POSTGRES_DB=customer-order-service
POSTGRES_HOST=localhost
POSTGRES_PORT=5432



# Africa's Talking Sandbox Credentials
# AT_API_KEY=atsk_fab81f0bce6f9d96401faa8f2e287bd16458e88e147ae65bfebd9f0a391e5453d4207535
AT_API_KEY=atsk_c5b5c683c000666aa32dc9537818ce2eb45254ce97256ffb5eac1cc28f139134ad5ceff3
AT_USERNAME="sandbox"
COMPANY_NAME=Donfiles

# OpenID Connect
OIDC_CLIENT_ID=customer_api
OIDC_CLIENT_SECRET=Dzd4MBKxgHkNibYQueyPYqiff0gl4nVK
OIDC_ISSUER=http://localhost:8080/realms/donfiles
REDIRECT_URL=http://localhost:8080/realms/donfiles
KEYCLOAK_SERVER_URL=http://localhost:8080
KEYCLOAK_REALM=donfiles
KEYCLOAK_ADMIN_USER=harman.muasa@mail.com
KEYCLOAK_ADMIN_PASSWORD=donfiles.online

OIDC_JWKS_URL=http://localhost:8080/realms/donfiles/protocol/openid-connect/certs



# dev mode
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
# sequence

sequenceDiagram
    participant Client
    participant API
    participant Keycloak
    
    Client->API: Login Request
    API->Keycloak: Token Request
    Keycloak-->API: JWT Tokens
    API-->>Client: Access/Refresh Tokens
    Client->API: API Request (with JWT)
    API->Keycloak: Token Validation
    Keycloak-->API: Validation Result
    API-->Client: Protected Data



# GraphQL
# postman url: http://localhost:8000/graphql/
#GraphQL Mutations
# Login
mutation Login($input: LoginInput!) {
  login(input: $input) {
    accessToken   
    refreshToken  
    userInfo {    
      email
      userId
      fullName
      roles
    }
    success
    message
  }
}
# Variables
{
  "input": {
    "username": "harman.muasa@gmail.com",
    "password": "donfiles.online"
  }
}
# response
"data": {
        "login": {
            "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJudHoxVEtILXZiMU54Wng0Ri1rQWpBbzZfYUFfeWRQNXlDYkZTaFh4UkEwIn0.eyJleHAiOjE3NDU0OTA3NzEsImlhdCI6MTc0NTQ5MDQ3MSwianRpIjoiYWYyMjE1NjQtZTJiZi00MGE4LWE1ZGMtNTYyMDllNGE3NjI2IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9kb25maWxlcyIsImF1ZCI6WyJyZWFsbS1tYW5hZ2VtZW50IiwiYnJva2VyIiwiYWNjb3VudCJdLCJzdWIiOiJjMGY4NmE3MS1kMzVhLTQzZjAtOTNjMC0yODAyZjg4ZWFmOWQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJjdXN0b21lcl9hcGkiLCJzaWQiOiJlYTFkOTcxMS05NzUzLTQ4YWMtOWYwYS0wZjc1NzU4MTUwOTEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGVmYXVsdC1yb2xlcy1kb25maWxlcyIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJyZWFsbS1tYW5hZ2VtZW50Ijp7InJvbGVzIjpbInZpZXctaWRlbnRpdHktcHJvdmlkZXJzIiwidmlldy1yZWFsbSIsIm1hbmFnZS1pZGVudGl0eS1wcm92aWRlcnMiLCJpbXBlcnNvbmF0aW9uIiwicmVhbG0tYWRtaW4iLCJjcmVhdGUtY2xpZW50IiwibWFuYWdlLXVzZXJzIiwicXVlcnktcmVhbG1zIiwidmlldy1hdXRob3JpemF0aW9uIiwicXVlcnktY2xpZW50cyIsInF1ZXJ5LXVzZXJzIiwibWFuYWdlLWV2ZW50cyIsIm1hbmFnZS1yZWFsbSIsInZpZXctZXZlbnRzIiwidmlldy11c2VycyIsInZpZXctY2xpZW50cyIsIm1hbmFnZS1hdXRob3JpemF0aW9uIiwibWFuYWdlLWNsaWVudHMiLCJxdWVyeS1ncm91cHMiXX0sImN1c3RvbWVyX2FwaSI6eyJyb2xlcyI6WyJ1bWFfcHJvdGVjdGlvbiIsImN1c3RvbWVyIl19LCJicm9rZXIiOnsicm9sZXMiOlsicmVhZC10b2tlbiJdfSwiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsInZpZXctYXBwbGljYXRpb25zIiwidmlldy1jb25zZW50Iiwidmlldy1ncm91cHMiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsIm1hbmFnZS1jb25zZW50IiwiZGVsZXRlLWFjY291bnQiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJIYXJtYW4gTXVhc2EiLCJwaG9uZV9udW1iZXIiOiIrMjU0NzIxNDU2OTkyIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiaGFybWFuLm11YXNhQGdtYWlsLmNvbSIsImdpdmVuX25hbWUiOiJIYXJtYW4iLCJmYW1pbHlfbmFtZSI6Ik11YXNhIiwiZW1haWwiOiJoYXJtYW4ubXVhc2FAZ21haWwuY29tIn0.lqDGAHDJPfgxM6hG3sT0Ux7vDmh6BneYMDGP4qWat3eBRyQNoCjqYYWErWJ90zQGTt0J4sMTd4FS0QBOLII4tZIQRa6ZtlHTmXKDFS0gA1EXHdKPqnjqIvDjnDCcSkIfR4xHJw3mjhN0EJJoUqUy4B6D7Ldw4JRRKgRuj_JljzMhxynP_4uWNxxYwY40RFEGzp9Bf2teCAxxUodQnkpC32-R-VdQTGi9NbFOeN5lK0AI3ClG9sGz65Qa5rySuArtbm93_xeM9cLKJEcUwCHm9QpLlLn0FuOGRzzyeMUY6cH_2yPyeX4gXJF5RehsIDVOLVibfGAwgXE1nNIy4xA84A",
            "refreshToken": "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIxOGQ4NjIxMS0zOTM4LTQwNTQtYjBiZS1lMDA0ODljODdiMzkifQ.eyJleHAiOjE3NDU0OTIyNzEsImlhdCI6MTc0NTQ5MDQ3MSwianRpIjoiYjQ2ODgyMzItMGZmMC00NmRlLTliMzgtYjQ4MWUyOGMxYWRjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9kb25maWxlcyIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9yZWFsbXMvZG9uZmlsZXMiLCJzdWIiOiJjMGY4NmE3MS1kMzVhLTQzZjAtOTNjMC0yODAyZjg4ZWFmOWQiLCJ0eXAiOiJSZWZyZXNoIiwiYXpwIjoiY3VzdG9tZXJfYXBpIiwic2lkIjoiZWExZDk3MTEtOTc1My00OGFjLTlmMGEtMGY3NTc1ODE1MDkxIiwic2NvcGUiOiJvcGVuaWQgYmFzaWMgd2ViLW9yaWdpbnMgZW1haWwgcHJvZmlsZSByb2xlcyBhY3IifQ.5fFjuP0OZpKjIutyhMIX8PTzVLEYXiXAC1ctIrWc4RUsyZlui9Br5KNpheorfJ7xy1_CzffwdhCrJ_bkCCVzhQ",
            "userInfo": {
                "email": "harman.muasa@gmail.com",
                "userId": "c0f86a71-d35a-43f0-93c0-2802f88eaf9d",
                "fullName": "Harman Muasa",
                "roles": [
                    "default-roles-donfiles",
                    "offline_access",
                    "uma_authorization"
                ]
            },
            "success": true,
            "message": "Login successful"
        }
    }
}
# create Order Mutation
mutation {
  createOrder(
    input: {
      price: 1200.0
      userId: "c0f86a71-d35a-43f0-93c0-2802f88eaf9d"
      orderDetails: "Deliver ASAP"
    }
  ) {
    success
    message
    errors
    order {
      id
      totalPrice
      customerId
      status
      createdAt
      createdBy
      orderDetails
    }
  }
}
# response
{
    "data": {
        "createOrder": {
            "success": true,
            "message": "Order created successfully!",
            "errors": [],
            "order": {
                "id": "235a2999-123e-4e36-afba-22e4057c44f9",
                "totalPrice": 1200.0,
                "customerId": "c0f86a71-d35a-43f0-93c0-2802f88eaf9d",
                "status": "NEW",
                "createdAt": "2025-04-24T10:29:30.646877+00:00",
                "createdBy": "c0f86a71-d35a-43f0-93c0-2802f88eaf9d",
                "orderDetails": "Deliver ASAP"
            }
        }
    }
}

# Confirm Order Mutation
mutation ConfirmOrder {
  confirmOrder(orderId: "ecbcab51-5bec-4dba-b9c3-e20e472f56a4") {
    order {
      id
      status
      totalPrice
      customerId
      createdAt
    }
    success
    message
    errors
  }
}
# response
{
    "data": {
        "confirmOrder": {
            "order": {
                "id": "235a2999-123e-4e36-afba-22e4057c44f9",
                "status": "CONFIRMED",
                "totalPrice": 1200.0,
                "customerId": "c0f86a71-d35a-43f0-93c0-2802f88eaf9d",
                "createdAt": "2025-04-24T10:29:30.646877+00:00"
            },
            "success": true,
            "message": "Order confirmed!",
            "errors": []
        }
    }
}
# Query Orders
query GetMyOrders {
  myOrders(status: "confirmed") {
    id
    status
    totalPrice
    createdAt
  }
}
# response
{
    "data": {
        "myOrders": [
            {
                "id": "235a2999-123e-4e36-afba-22e4057c44f9",
                "status": "CONFIRMED",
                "totalPrice": 1200.0,
                "createdAt": "2025-04-24T10:29:30.646877+00:00"
            },
            {
                "id": "0c4dc88a-2b61-4655-98e9-2b159f8b772c",
                "status": "CONFIRMED",
                "totalPrice": 1200.0,
                "createdAt": "2025-04-23T20:09:39.275196+00:00"
            },
            {
                "id": "58895946-dcf8-460d-84bc-f0ab76784bb1",
                "status": "CONFIRMED",
                "totalPrice": 1200.0,
                "createdAt": "2025-04-23T20:07:05.576235+00:00"
            },
            {
                "id": "4061e4ab-fd66-4f90-ab1a-9d20ccf8d3a3",
                "status": "CONFIRMED",
                "totalPrice": 1200.0,
                "createdAt": "2025-04-23T20:05:02.776457+00:00"
            },
            {
                "id": "d4c29288-a934-46e8-822a-68163f510904",
                "status": "CONFIRMED",
                "totalPrice": 1200.0,
                "createdAt": "2025-04-23T20:02:51.746726+00:00"
            },
            {
                "id": "6694aa12-56ee-489e-8636-1b729e66ac6c",
                "status": "CONFIRMED",
                "totalPrice": 1200.0,
                "createdAt": "2025-04-23T14:47:34.039544+00:00"
            },
# testing
pytest