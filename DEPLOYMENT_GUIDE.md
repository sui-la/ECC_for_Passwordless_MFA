# 🚀 Deployment Guide

## Overview

This guide covers deploying the ECC Passwordless MFA system to production environments with enterprise-grade security, monitoring, and scalability.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Application   │    │   Database      │
│   (Nginx/ALB)   │◄──►│   Containers    │◄──►│  (PostgreSQL)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │     Redis       │
                       │   (Cluster)     │
                       └─────────────────┘
```

## 📋 Prerequisites

### Infrastructure Requirements
- **CPU**: 2+ cores per container
- **Memory**: 4GB+ RAM total
- **Storage**: 50GB+ SSD storage
- **Network**: High-speed internet connection
- **SSL Certificate**: Valid SSL certificate for your domain

### Software Requirements
- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Nginx**: 1.18+ (for reverse proxy)
- **PostgreSQL**: 13+ (or managed service)
- **Redis**: 6+ (or managed service)

## 🔧 Production Configuration

### 1. Environment Variables

Create a production `.env` file:

```env
# Application Configuration
FLASK_ENV=production
SECRET_KEY=your-super-secure-secret-key-here
JWT_SECRET_KEY=your-super-secure-jwt-secret-key-here

# Database Configuration
DATABASE_URL=postgresql://username:password@host:5432/database
POSTGRES_USER=your_db_user
POSTGRES_PASSWORD=your_secure_db_password
POSTGRES_DB=ecc_mfa_prod

# Redis Configuration
REDIS_URL=redis://username:password@host:6379/0

# Email Configuration (Required for production)
EMAIL_SERVER=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-specific-password
EMAIL_USE_TLS=true

# Security Configuration
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Monitoring Configuration
LOG_LEVEL=INFO
ENABLE_METRICS=true
ENABLE_AUDIT_LOGS=true

# Rate Limiting
RATE_LIMIT_AUTH=5
RATE_LIMIT_REGISTRATION=3
RATE_LIMIT_RECOVERY=3
```

### 2. Generate Secure Secrets

```bash
# Generate secure secret keys
python generate_secret.py

# Or manually generate using:
openssl rand -hex 32
```

### 3. SSL Certificate Setup

#### Using Let's Encrypt (Recommended)
```bash
# Install Certbot
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

#### Using Custom Certificate
```bash
# Place your certificate files
sudo cp your-certificate.crt /etc/ssl/certs/
sudo cp your-private-key.key /etc/ssl/private/
```

## 🐳 Docker Production Deployment

### 1. Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/ssl
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - backend
      - frontend
    restart: unless-stopped

  backend:
    build: 
      context: ./backend
      dockerfile: Dockerfile.prod
    environment:
      - FLASK_ENV=production
    env_file:
      - .env
    volumes:
      - ./logs/backend:/app/logs
    depends_on:
      - db
      - redis
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile.prod
    volumes:
      - ./logs/frontend:/app/logs
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'

  db:
    image: postgres:15
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./logs/postgres:/var/log/postgresql
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '1.0'
        reservations:
          memory: 1G
          cpus: '0.5'

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
      - ./logs/redis:/var/log/redis
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'

volumes:
  postgres_data:
  redis_data:
```

### 2. Production Dockerfile

Create `backend/Dockerfile.prod`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--timeout", "120", "app:app"]
```

Create `frontend/Dockerfile.prod`:

```dockerfile
FROM node:16-alpine as build

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY . .

# Build application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built application
COPY --from=build /app/build /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
```

### 3. Nginx Configuration

Create `nginx.conf`:

```nginx
upstream backend {
    server backend:5000;
}

upstream frontend {
    server frontend:80;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/ssl/certs/yourdomain.com.crt;
    ssl_certificate_key /etc/ssl/private/yourdomain.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # API Routes
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # Authentication endpoints (stricter rate limiting)
    location ~ ^/(auth|register|recovery)/ {
        limit_req zone=auth burst=5 nodelay;
        
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check (no rate limiting)
    location /health {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Frontend
    location / {
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🚀 Deployment Steps

### 1. Initial Setup

```bash
# Clone repository
git clone <your-repo-url>
cd ECCforPasswordlessMFA

# Create production environment
cp env.example .env
# Edit .env with production values

# Generate secrets
python generate_secret.py

# Create log directories
mkdir -p logs/{nginx,backend,frontend,postgres,redis}
```

### 2. Database Setup

```bash
# Start database only
docker-compose -f docker-compose.prod.yml up -d db

# Wait for database to be ready
sleep 10

# Run database migrations
docker-compose -f docker-compose.prod.yml exec backend python -m flask create-db
```

### 3. Deploy Application

```bash
# Build and start all services
docker-compose -f docker-compose.prod.yml up -d --build

# Check status
docker-compose -f docker-compose.prod.yml ps

# Check logs
docker-compose -f docker-compose.prod.yml logs -f
```

### 4. Verify Deployment

```bash
# Health check
curl -k https://yourdomain.com/health

# API documentation
curl -k https://yourdomain.com/api/docs

# Database optimization
curl -k https://yourdomain.com/api/database/optimization/score
```

## 🔒 Security Hardening

### 1. Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# iptables (CentOS/RHEL)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -j DROP
```

### 2. Database Security

```sql
-- Create dedicated user with limited privileges
CREATE USER ecc_mfa_user WITH PASSWORD 'secure_password';
GRANT CONNECT ON DATABASE ecc_mfa TO ecc_mfa_user;
GRANT USAGE ON SCHEMA public TO ecc_mfa_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ecc_mfa_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ecc_mfa_user;

-- Enable SSL
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/path/to/server.crt';
ALTER SYSTEM SET ssl_key_file = '/path/to/server.key';
```

### 3. Redis Security

```bash
# Configure Redis with authentication
echo "requirepass your_secure_redis_password" >> /etc/redis/redis.conf
echo "bind 127.0.0.1" >> /etc/redis/redis.conf
echo "protected-mode yes" >> /etc/redis/redis.conf
```

### 4. Container Security

```bash
# Run containers as non-root
# (Already configured in Dockerfile.prod)

# Enable Docker content trust
export DOCKER_CONTENT_TRUST=1

# Scan images for vulnerabilities
docker scan your-image-name
```

## 📊 Monitoring & Alerting

### 1. Health Monitoring

```bash
# Create monitoring script
cat > monitor.sh << 'EOF'
#!/bin/bash

# Health check
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" https://yourdomain.com/health)
if [ "$HEALTH" != "200" ]; then
    echo "Health check failed: $HEALTH"
    # Send alert
fi

# Database optimization score
SCORE=$(curl -s https://yourdomain.com/api/database/optimization/score | jq -r '.optimization_score')
if [ "$SCORE" -lt 90 ]; then
    echo "Database optimization score low: $SCORE"
    # Send alert
fi
EOF

chmod +x monitor.sh

# Add to crontab
echo "*/5 * * * * /path/to/monitor.sh" | crontab -
```

### 2. Log Monitoring

```bash
# Install log monitoring tools
sudo apt-get install logwatch

# Configure logwatch
sudo nano /etc/logwatch/conf/logwatch.conf

# Add to crontab for daily reports
echo "0 7 * * * /usr/sbin/logwatch --output mail --mailto admin@yourdomain.com" | crontab -
```

### 3. Performance Monitoring

```bash
# Install monitoring tools
sudo apt-get install htop iotop nethogs

# Monitor system resources
htop
iotop
nethogs
```

## 🔄 Backup & Recovery

### 1. Database Backup

```bash
# Create backup script
cat > backup.sh << 'EOF'
#!/bin/bash

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/database"

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
docker-compose -f docker-compose.prod.yml exec -T db pg_dump -U $POSTGRES_USER $POSTGRES_DB > $BACKUP_DIR/backup_$DATE.sql

# Compress backup
gzip $BACKUP_DIR/backup_$DATE.sql

# Keep only last 7 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete
EOF

chmod +x backup.sh

# Add to crontab (daily at 2 AM)
echo "0 2 * * * /path/to/backup.sh" | crontab -
```

### 2. Application Backup

```bash
# Backup application data
tar -czf /backups/app/app_$(date +%Y%m%d_%H%M%S).tar.gz \
    /path/to/application/logs \
    /path/to/application/uploads
```

### 3. Recovery Procedures

```bash
# Database recovery
docker-compose -f docker-compose.prod.yml exec -T db psql -U $POSTGRES_USER $POSTGRES_DB < backup_20250101_120000.sql

# Application recovery
tar -xzf app_20250101_120000.tar.gz -C /path/to/application/
```

## 🔧 Maintenance

### 1. Regular Updates

```bash
# Update system packages
sudo apt-get update && sudo apt-get upgrade -y

# Update Docker images
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d

# Clean up old images
docker image prune -f
```

### 2. Log Rotation

```bash
# Configure logrotate
sudo nano /etc/logrotate.d/ecc-mfa

# Add configuration
/path/to/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
```

### 3. Performance Optimization

```bash
# Monitor database performance
curl https://yourdomain.com/api/database/optimization/report

# Check system resources
curl https://yourdomain.com/api/monitoring/system/status

# Analyze slow queries
curl https://yourdomain.com/api/monitoring/performance
```

## 🚨 Troubleshooting

### Common Issues

**1. Database Connection Issues**
```bash
# Check database status
docker-compose -f docker-compose.prod.yml logs db

# Test connection
docker-compose -f docker-compose.prod.yml exec backend python -c "
from database.models import db
print('Database connected:', db.engine.execute('SELECT 1').scalar())
"
```

**2. SSL Certificate Issues**
```bash
# Check certificate validity
openssl x509 -in /etc/ssl/certs/yourdomain.com.crt -text -noout

# Test SSL connection
openssl s_client -connect yourdomain.com:443 -servername yourdomain.com
```

**3. Rate Limiting Issues**
```bash
# Check rate limit logs
docker-compose -f docker-compose.prod.yml logs backend | grep "rate limit"

# Adjust rate limits in nginx.conf if needed
```

**4. Memory Issues**
```bash
# Check memory usage
docker stats

# Increase memory limits in docker-compose.prod.yml
```

## 📈 Scaling

### 1. Horizontal Scaling

```yaml
# Add to docker-compose.prod.yml
services:
  backend:
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
```

### 2. Load Balancer Configuration

```nginx
# Update nginx.conf for multiple backend instances
upstream backend {
    server backend1:5000;
    server backend2:5000;
    server backend3:5000;
}
```

### 3. Database Scaling

```bash
# Consider using managed database services
# - AWS RDS
# - Google Cloud SQL
# - Azure Database for PostgreSQL
```

## 📞 Support

### Emergency Contacts
- **System Administrator**: admin@yourdomain.com
- **Database Administrator**: dba@yourdomain.com
- **Security Team**: security@yourdomain.com

### Escalation Procedures
1. **Level 1**: Check logs and restart services
2. **Level 2**: Rollback to previous version
3. **Level 3**: Contact development team
4. **Level 4**: Emergency maintenance window

---

**🎉 Your ECC Passwordless MFA System is Now Production-Ready!**

This deployment guide ensures your system is secure, scalable, and maintainable in production environments.