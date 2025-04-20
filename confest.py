import os
from dotenv import load_dotenv

def pytest_configure():
    load_dotenv()
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'customer_order_api.settings')
