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

WORKDIR /app

# Copy project
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "apksensify.py"]
