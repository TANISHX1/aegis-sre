


# Base image with Python
FROM python:3.11-slim

# Install system dependencies (curl for Coral, git for commits)
RUN apt-get update && apt-get install -y curl git unzip wget && rm -rf /var/lib/apt/lists/*

# Install Node.js (Required by Reflex for the frontend Next.js compilation)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

# Install Coral CLI
RUN curl -fsSL https://withcoral.com/install.sh | sh
ENV PATH="/root/.coral/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Expose the frontend and backend ports
EXPOSE 3000 8000

# Run setup and Reflex at runtime
CMD ["./entrypoint.sh"]
