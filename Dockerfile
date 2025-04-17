FROM python:3.11

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1


WORKDIR /customer_order_api


COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt


COPY . .

# Run server (change this if using something like gunicorn in prod)
CMD ["python", "api/manage.py", "runserver", "0.0.0.0:8000"]
