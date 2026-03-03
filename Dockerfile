FROM python:3.11-slim-bookworm

LABEL maintainer="Jerry"
LABEL tool="APKSensify"

# Install system dependencies
RUN apt-get update && \
    apt-get install -y \
        openjdk-17-jre \
        apktool \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# Set working directory for project files
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set runtime working directory to /data
# This is where user will mount APKs
WORKDIR /data

# Run apksensify from /app
ENTRYPOINT ["python", "/app/apksensify.py"]
