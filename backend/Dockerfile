# Build stage (for dependencies)
FROM python:3.11-slim AS build
WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim
WORKDIR /app
COPY --from=build /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
COPY . .

# Install additional dependencies for debugging
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Set Flask app environment variable
ENV FLASK_APP=app_factory.py

EXPOSE 5000

# Run Flask app directly
CMD ["python", "-u", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]