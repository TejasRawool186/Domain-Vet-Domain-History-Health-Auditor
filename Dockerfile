# Dockerfile for Domain Vet - Apify Actor
FROM apify/actor-python:3.11

# Copy requirements and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . ./

# Run the actor from src directory
CMD ["python", "src/main.py"]
