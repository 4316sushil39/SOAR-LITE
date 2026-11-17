FROM python:3.11-slim

WORKDIR /app

# Install system utilities for network inspection & containment
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    iptables \
    net-tools \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create required operational directories
RUN mkdir -p monitored_files quarantine_vault

EXPOSE 8000 8501

ENV EXECUTION_MODE=simulation \
    SQLITE_DB_PATH=/app/soar_lite.db \
    PYTHONUNBUFFERED=1

# Default entrypoint: FastAPI with Live SOC Control Room Dashboard
CMD ["uvicorn", "soar_lite.main:app", "--host", "0.0.0.0", "--port", "8000"]
