# Start with a lightweight Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create app directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy project files
COPY . .

# Run migrations and start server
CMD ["sh", "-c", "python manage.py migrate && gunicorn customer_order_api.wsgi:application --bind 0.0.0.0:$PORT"]





# FROM python:3.11

# # Set environment variables
# ENV PYTHONDONTWRITEBYTECODE 1
# ENV PYTHONUNBUFFERED 1


# WORKDIR /customer_order_api


# RUN apt-get update \
#     && apt-get install -y build-essential libpq-dev gcc \
#     && apt-get clean


# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# COPY . .


# RUN python manage.py collectstatic --noinput || true

# RUN adduser --disabled-password appuser
# USER appuser

# EXPOSE 8000

# RUN pip install --upgrade pip && pip install -r requirements.txt



# CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
