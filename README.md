# customer-order-service API

[![CI/CD](https://github.com/Muasa-harman/customer-order-service/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/Muasa-harman/customer-order-service/actions)
[![Codecov](https://codecov.io/gh/yourusername/customer-order-service/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/ecommerce-api)

A Django-based GraphQL API for managing customers and orders, with OpenID Connect authentication and SMS notifications.

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
git clone 
cd 
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt# customer-order-api


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
# Query Orders
query GetMyOrders {
  myOrders(status: "confirmed") {
    id
    status
    totalPrice
    createdAt
  }
}