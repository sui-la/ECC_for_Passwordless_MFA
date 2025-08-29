"""
Monitoring Blueprint for ECC Passwordless MFA.
Handles health checks, system monitoring, and performance metrics.
"""

from flask import Blueprint, jsonify, request, current_app
from monitoring_system import (
    get_comprehensive_health_status, get_metrics_history, 
    record_request_metric, update_session_metrics, update_user_metrics
)
from database_optimization import (
    get_database_optimization_report, record_database_query,
    generate_index_script, get_optimization_score
)
from performance_optimizer import PerformanceOptimizer, performance_monitor
from utils.security_headers import get_security_report
from utils.logging_config import get_log_stats
from api_documentation import create_api_documentation, generate_api_spec, get_api_endpoints
from datetime import datetime

monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route('/health', methods=['GET'])
def health_check():
    """Enhanced health check endpoint."""
    try:
        health_data = get_comprehensive_health_status()
        
        # Return simplified health status for backward compatibility
        return jsonify({
            'status': health_data['overall'],
            'database': health_data['services']['database']['status'],
            'redis': health_data['services']['redis']['status'],
            'rate_limiting': health_data['services']['rate_limiting']['status'],
            'timestamp': health_data['timestamp'],
            'version': health_data['version'],
            'check_duration_ms': health_data['check_duration_ms']
        }), 200
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@monitoring_bp.route('/security', methods=['GET'])
def security_info():
    """Get security configuration information."""
    try:
        security_report = get_security_report()
        
        # Remove sensitive information for public endpoint
        public_report = {
            'environment': security_report['environment'],
            'security_headers_count': len(security_report['security_headers']),
            'csp_validation': security_report['csp_validation'],
            'hsts_enabled': 'Strict-Transport-Security' in security_report['hsts_config'],
            'recommendations': security_report['recommendations']
        }
        
        return jsonify(public_report), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to get security information',
            'message': str(e)
        }), 500

@monitoring_bp.route('/logs/stats', methods=['GET'])
def get_log_statistics():
    """Get logging statistics."""
    try:
        stats = get_log_stats()
        return jsonify(stats), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to get log statistics',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/docs', methods=['GET'])
def api_documentation():
    """Serve API documentation."""
    api_docs = create_api_documentation()
    return api_docs.doc()

@monitoring_bp.route('/api/spec', methods=['GET'])
def api_specification():
    """Get OpenAPI specification."""
    try:
        spec = generate_api_spec()
        return jsonify(spec), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to generate API specification',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/endpoints', methods=['GET'])
def api_endpoints():
    """Get list of all API endpoints."""
    try:
        endpoints = get_api_endpoints()
        return jsonify({
            'endpoints': endpoints,
            'total_endpoints': sum(len(v) for v in endpoints.values()),
            'categories': list(endpoints.keys())
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get API endpoints',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/monitoring/health/comprehensive', methods=['GET'])
def comprehensive_health_check():
    """Get comprehensive health status including all metrics."""
    try:
        health_data = get_comprehensive_health_status()
        return jsonify(health_data), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get comprehensive health status',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/monitoring/metrics/history', methods=['GET'])
def get_metrics_history_endpoint():
    """Get historical metrics data."""
    try:
        history = get_metrics_history()
        return jsonify({
            'metrics_history': history,
            'total_records': len(history),
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get metrics history',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/monitoring/performance', methods=['GET'])
def get_performance_report():
    """Get performance monitoring report."""
    try:
        report = performance_monitor.get_performance_report()
        return jsonify(report), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get performance report',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/monitoring/system/status', methods=['GET'])
def get_system_status():
    """Get real-time system status."""
    try:
        from monitoring_system import system_metrics
        metrics = system_metrics.collect_system_metrics()
        return jsonify({
            'system_status': metrics,
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get system status',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/database/optimization/report', methods=['GET'])
def get_database_optimization_report_endpoint():
    """Get comprehensive database optimization report."""
    try:
        report = get_database_optimization_report()
        return jsonify(report), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get database optimization report',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/database/optimization/score', methods=['GET'])
def get_database_optimization_score():
    """Get current database optimization score."""
    try:
        score = get_optimization_score()
        return jsonify({
            'optimization_score': score,
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to get optimization score',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/database/optimization/indexes', methods=['GET'])
def get_index_optimization_script():
    """Get SQL script for recommended indexes."""
    try:
        script = generate_index_script()
        return jsonify({
            'index_script': script,
            'timestamp': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'error': 'Failed to generate index script',
            'message': str(e)
        }), 500

@monitoring_bp.route('/api/performance/optimize', methods=['POST'])
def run_performance_optimization():
    """Run comprehensive performance optimization."""
    try:
        optimizer = PerformanceOptimizer()
        results = optimizer.run_comprehensive_optimization()
        
        return jsonify({
            'status': 'success',
            'message': 'Performance optimization completed',
            'results': results
        }), 200
    except Exception as e:
        return jsonify({
            'error': {
                'code': 'optimization_error',
                'message': 'Failed to run performance optimization',
                'details': str(e)
            }
        }), 500

@monitoring_bp.route('/api/performance/stats', methods=['GET'])
def get_performance_stats():
    """Get current performance statistics."""
    try:
        stats = performance_monitor.get_performance_stats()
        return jsonify({
            'status': 'success',
            'message': 'Performance statistics retrieved',
            'stats': stats
        }), 200
    except Exception as e:
        return jsonify({
            'error': {
                'code': 'stats_error',
                'message': 'Failed to get performance statistics',
                'details': str(e)
            }
        }), 500

@monitoring_bp.route('/api/performance/cache/clear', methods=['POST'])
def clear_performance_cache():
    """Clear performance cache."""
    try:
        optimizer = PerformanceOptimizer()
        optimizer.redis_client.flushdb()
        return jsonify({
            'status': 'success',
            'message': 'Performance cache cleared'
        }), 200
    except Exception as e:
        return jsonify({
            'error': {
                'code': 'cache_error',
                'message': 'Failed to clear performance cache',
                'details': str(e)
            }
        }), 500
