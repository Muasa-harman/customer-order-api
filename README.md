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
git clone https://github.com/Muasa-harman/customer-order-service.git
cd customer-order-service
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt# customer-order-api
