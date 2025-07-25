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
EXPOSE 5000
CMD ["python", "-u", "app.py"]