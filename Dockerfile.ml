FROM python:3.10-slim

WORKDIR /app

# Install system dependencies (psycopg2 needs libpq)
RUN apt-get update && apt-get install -y \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose Dashboard Port
EXPOSE 5000

# Entrypoint configures waiting for database and starting both daemon and dashboard
CMD ["python", "start_all.py"]
