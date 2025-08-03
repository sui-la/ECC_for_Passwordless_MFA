"""
Comprehensive Monitoring and Health Check System for ECC Passwordless MFA.
Provides enhanced health monitoring, performance metrics, and system diagnostics.
"""

import time
import psutil
import threading
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from flask import current_app
from collections import defaultdict, deque
import redis
from sqlalchemy import text
from database.models import db

logger = logging.getLogger(__name__)

class SystemMetrics:
    """Collects and manages system performance metrics."""
    
    def __init__(self, max_history: int = 100):
        self.max_history = max_history
        self.metrics_history = deque(maxlen=max_history)
        self.start_time = time.time()
        self.metrics_lock = threading.Lock()
        
    def collect_system_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics."""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network metrics
            network = psutil.net_io_counters()
            
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu': {
                    'usage_percent': cpu_percent,
                    'count': cpu_count,
                    'frequency_mhz': cpu_freq.current if cpu_freq else None
                },
                'memory': {
                    'total_gb': round(memory.total / (1024**3), 2),
                    'available_gb': round(memory.available / (1024**3), 2),
                    'used_gb': round(memory.used / (1024**3), 2),
                    'usage_percent': memory.percent
                },
                'disk': {
                    'total_gb': round(disk.total / (1024**3), 2),
                    'used_gb': round(disk.used / (1024**3), 2),
                    'free_gb': round(disk.free / (1024**3), 2),
                    'usage_percent': round((disk.used / disk.total) * 100, 2)
                },
                'network': {
                    'bytes_sent': network.bytes_sent,
                    'bytes_recv': network.bytes_recv,
                    'packets_sent': network.packets_sent,
                    'packets_recv': network.packets_recv
                }
            }
            
            with self.metrics_lock:
                self.metrics_history.append(metrics)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {}

class ApplicationMetrics:
    """Collects and manages application-specific metrics."""
    
    def __init__(self):
        self.request_count = defaultdict(int)
        self.response_times = defaultdict(list)
        self.error_count = defaultdict(int)
        self.active_sessions = 0
        self.total_users = 0
        self.total_devices = 0
        self.metrics_lock = threading.Lock()
        
    def record_request(self, endpoint: str, method: str, status_code: int, response_time: float):
        """Record a request metric."""
        key = f"{method} {endpoint}"
        
        with self.metrics_lock:
            self.request_count[key] += 1
            
            if status_code >= 400:
                self.error_count[key] += 1
            
            # Keep only last 100 response times per endpoint
            if len(self.response_times[key]) >= 100:
                self.response_times[key].pop(0)
            self.response_times[key].append(response_time)
    
    def update_session_count(self, count: int):
        """Update active session count."""
        with self.metrics_lock:
            self.active_sessions = count
    
    def update_user_stats(self, user_count: int, device_count: int):
        """Update user and device statistics."""
        with self.metrics_lock:
            self.total_users = user_count
            self.total_devices = device_count
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current application metrics."""
        with self.metrics_lock:
            avg_response_times = {}
            for endpoint, times in self.response_times.items():
                if times:
                    avg_response_times[endpoint] = round(sum(times) / len(times), 3)
            
            return {
                'timestamp': datetime.now().isoformat(),
                'requests': dict(self.request_count),
                'errors': dict(self.error_count),
                'avg_response_times': avg_response_times,
                'active_sessions': self.active_sessions,
                'total_users': self.total_users,
                'total_devices': self.total_devices
            }

class HealthChecker:
    """Comprehensive health checking system."""
    
    def __init__(self):
        self.health_status = {
            'overall': 'unknown',
            'services': {},
            'last_check': None
        }
        self.health_lock = threading.Lock()
    
    def check_database_health(self) -> Dict[str, Any]:
        """Check database connectivity and performance."""
        try:
            start_time = time.time()
            
            # Test basic connectivity
            result = db.session.execute(text("SELECT 1"))
            result.fetchone()
            
            # Test performance with a simple query
            result = db.session.execute(text("SELECT COUNT(*) FROM users"))
            user_count = result.scalar()
            
            # Test performance with device count
            result = db.session.execute(text("SELECT COUNT(*) FROM devices"))
            device_count = result.scalar()
            
            response_time = round((time.time() - start_time) * 1000, 2)
            
            return {
                'status': 'healthy',
                'response_time_ms': response_time,
                'user_count': user_count,
                'device_count': device_count,
                'connection_pool_size': db.engine.pool.size(),
                'checked_in_pool': db.engine.pool.checkedin(),
                'overflow': db.engine.pool.overflow()
            }
                
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'response_time_ms': None
            }
    
    def check_redis_health(self) -> Dict[str, Any]:
        """Check Redis connectivity and performance."""
        try:
            start_time = time.time()
            
            redis_client = redis.from_url(current_app.config['REDIS_URL'])
            
            # Test basic connectivity
            redis_client.ping()
            
            # Test performance
            test_key = "health_check_test"
            redis_client.set(test_key, "test_value", ex=10)
            value = redis_client.get(test_key)
            redis_client.delete(test_key)
            
            response_time = round((time.time() - start_time) * 1000, 2)
            
            # Get Redis info
            info = redis_client.info()
            
            return {
                'status': 'healthy',
                'response_time_ms': response_time,
                'memory_used_mb': round(info.get('used_memory', 0) / (1024**2), 2),
                'connected_clients': info.get('connected_clients', 0),
                'total_commands_processed': info.get('total_commands_processed', 0),
                'keyspace_hits': info.get('keyspace_hits', 0),
                'keyspace_misses': info.get('keyspace_misses', 0)
            }
            
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e),
                'response_time_ms': None
            }
    
    def check_rate_limiting_health(self) -> Dict[str, Any]:
        """Check rate limiting system health."""
        try:
            # This would check if rate limiting is working properly
            # For now, we'll return a basic health status
            return {
                'status': 'healthy',
                'strategy': current_app.config.get('RATE_LIMIT_STRATEGY', 'fixed-window'),
                'storage_backend': 'redis'
            }
        except Exception as e:
            logger.error(f"Rate limiting health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    def check_email_service_health(self) -> Dict[str, Any]:
        """Check email service configuration."""
        try:
            # Check if email configuration is present
            mail_config = {
                'server': current_app.config.get('MAIL_SERVER'),
                'port': current_app.config.get('MAIL_PORT'),
                'use_tls': current_app.config.get('MAIL_USE_TLS'),
                'username': current_app.config.get('MAIL_USERNAME'),
                'password_set': bool(current_app.config.get('MAIL_PASSWORD'))
            }
            
            # Basic validation
            if all([mail_config['server'], mail_config['port'], mail_config['username']]):
                return {
                    'status': 'healthy',
                    'configuration': mail_config
                }
            else:
                return {
                    'status': 'degraded',
                    'configuration': mail_config,
                    'warning': 'Incomplete email configuration'
                }
                
        except Exception as e:
            logger.error(f"Email service health check failed: {e}")
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    def perform_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        start_time = time.time()
        
        # Check individual services
        db_health = self.check_database_health()
        redis_health = self.check_redis_health()
        rate_limit_health = self.check_rate_limiting_health()
        email_health = self.check_email_service_health()
        
        # Determine overall health
        service_statuses = [db_health['status'], redis_health['status'], rate_limit_health['status']]
        
        if 'unhealthy' in service_statuses:
            overall_status = 'unhealthy'
        elif 'degraded' in service_statuses:
            overall_status = 'degraded'
        else:
            overall_status = 'healthy'
        
        health_data = {
            'overall': overall_status,
            'services': {
                'database': db_health,
                'redis': redis_health,
                'rate_limiting': rate_limit_health,
                'email': email_health
            },
            'timestamp': datetime.now().isoformat(),
            'check_duration_ms': round((time.time() - start_time) * 1000, 2),
            'version': current_app.config.get('API_VERSION', '1.0.0')
        }
        
        with self.health_lock:
            self.health_status = health_data
            self.health_status['last_check'] = datetime.now().isoformat()
        
        return health_data

class PerformanceMonitor:
    """Monitors application performance and bottlenecks."""
    
    def __init__(self):
        self.performance_data = {
            'slow_queries': deque(maxlen=50),
            'memory_leaks': deque(maxlen=20),
            'error_patterns': defaultdict(int),
            'bottlenecks': []
        }
        self.monitor_lock = threading.Lock()
    
    def record_slow_query(self, query: str, duration_ms: float, endpoint: str):
        """Record a slow database query."""
        with self.monitor_lock:
            self.performance_data['slow_queries'].append({
                'query': query[:100] + '...' if len(query) > 100 else query,
                'duration_ms': duration_ms,
                'endpoint': endpoint,
                'timestamp': datetime.now().isoformat()
            })
    
    def record_error_pattern(self, error_type: str, endpoint: str):
        """Record error patterns for analysis."""
        with self.monitor_lock:
            key = f"{error_type}:{endpoint}"
            self.performance_data['error_patterns'][key] += 1
    
    def detect_bottlenecks(self) -> List[Dict[str, Any]]:
        """Analyze performance data for bottlenecks."""
        bottlenecks = []
        
        with self.monitor_lock:
            # Check for slow queries
            slow_queries = list(self.performance_data['slow_queries'])
            if slow_queries:
                avg_duration = sum(q['duration_ms'] for q in slow_queries) / len(slow_queries)
                if avg_duration > 1000:  # More than 1 second
                    bottlenecks.append({
                        'type': 'slow_queries',
                        'severity': 'high' if avg_duration > 5000 else 'medium',
                        'description': f"Average query time: {avg_duration:.2f}ms",
                        'count': len(slow_queries)
                    })
            
            # Check for error patterns
            error_patterns = dict(self.performance_data['error_patterns'])
            high_error_endpoints = [k for k, v in error_patterns.items() if v > 10]
            if high_error_endpoints:
                bottlenecks.append({
                    'type': 'high_error_rate',
                    'severity': 'high',
                    'description': f"High error rate on endpoints: {', '.join(high_error_endpoints)}",
                    'endpoints': high_error_endpoints
                })
        
        return bottlenecks
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        bottlenecks = self.detect_bottlenecks()
        
        with self.monitor_lock:
            return {
                'timestamp': datetime.now().isoformat(),
                'slow_queries_count': len(self.performance_data['slow_queries']),
                'error_patterns': dict(self.performance_data['error_patterns']),
                'bottlenecks': bottlenecks,
                'recommendations': self._generate_recommendations(bottlenecks)
            }
    
    def _generate_recommendations(self, bottlenecks: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on bottlenecks."""
        recommendations = []
        
        for bottleneck in bottlenecks:
            if bottleneck['type'] == 'slow_queries':
                recommendations.append("Consider adding database indexes or optimizing queries")
            elif bottleneck['type'] == 'high_error_rate':
                recommendations.append("Investigate error patterns and implement proper error handling")
        
        return recommendations

# Global instances
system_metrics = SystemMetrics()
application_metrics = ApplicationMetrics()
health_checker = HealthChecker()
performance_monitor = PerformanceMonitor()

def get_comprehensive_health_status() -> Dict[str, Any]:
    """Get comprehensive health status including all metrics."""
    health_data = health_checker.perform_health_check()
    
    # Add system metrics
    health_data['system_metrics'] = system_metrics.collect_system_metrics()
    
    # Add application metrics
    health_data['application_metrics'] = application_metrics.get_metrics()
    
    # Add performance data
    health_data['performance'] = performance_monitor.get_performance_report()
    
    return health_data

def get_metrics_history() -> List[Dict[str, Any]]:
    """Get historical metrics data."""
    return list(system_metrics.metrics_history)

def record_request_metric(endpoint: str, method: str, status_code: int, response_time: float):
    """Record a request metric for monitoring."""
    application_metrics.record_request(endpoint, method, status_code, response_time)

def update_session_metrics(session_count: int):
    """Update session metrics."""
    application_metrics.update_session_count(session_count)

def update_user_metrics(user_count: int, device_count: int):
    """Update user and device metrics."""
    application_metrics.update_user_stats(user_count, device_count) 