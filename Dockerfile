# Dockerfile for Domain Vet - Apify Actor
FROM apify/actor-python:3.11

# Copy requirements and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . ./

# Set working directory
WORKDIR /home/myuser

# Run the actor
CMD ["python", "-m", "src.main"]
