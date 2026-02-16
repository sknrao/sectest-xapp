FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    curl \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt/xapp

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/

# Create certificate directory
RUN mkdir -p /opt/certs

# Set Python path
ENV PYTHONPATH=/opt/xapp/src

# Create non-root user
RUN useradd -m -u 1000 xappuser && \
    chown -R xappuser:xappuser /opt/xapp

USER xappuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD python -c "import requests; requests.get('http://localhost:8080/health')"

# Run xApp
CMD ["python", "-m", "src.main"]