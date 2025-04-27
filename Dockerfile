FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y nmap nikto && \
    rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your code
COPY . .

# Expose port
EXPOSE 5000

# Start the app using python3 main.py
CMD ["python3", "main.py"] 