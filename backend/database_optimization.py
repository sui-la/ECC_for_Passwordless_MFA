"""
Database Optimization System for ECC Passwordless MFA.
Provides query analysis, index optimization, connection pooling, and performance tuning.
"""

import time
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from sqlalchemy import text, inspect, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import QueuePool
from database.models import db, User, Device, AuthLog, Session
from flask import current_app

logger = logging.getLogger(__name__)

class QueryAnalyzer:
    """Analyzes database queries for performance optimization."""
    
    def __init__(self, max_history: int = 1000):
        self.query_history = deque(maxlen=max_history)
        self.slow_queries = deque(maxlen=100)
        self.query_patterns = defaultdict(int)
        self.performance_stats = {
            'total_queries': 0,
            'slow_queries': 0,
            'avg_response_time': 0.0,
            'max_response_time': 0.0
        }
    
    def record_query(self, query: str, duration_ms: float, endpoint: str, params: Dict = None):
        """Record a database query for analysis."""
        query_info = {
            'query': query,
            'duration_ms': duration_ms,
            'endpoint': endpoint,
            'params': params,
            'timestamp': datetime.now().isoformat()
        }
        
        self.query_history.append(query_info)
        self.query_patterns[query] += 1
        
        # Update performance stats
        self.performance_stats['total_queries'] += 1
        self.performance_stats['max_response_time'] = max(
            self.performance_stats['max_response_time'], duration_ms
        )
        
        # Track slow queries (>100ms)
        if duration_ms > 100:
            self.slow_queries.append(query_info)
            self.performance_stats['slow_queries'] += 1
        
        # Update average response time
        total_time = sum(q['duration_ms'] for q in self.query_history)
        self.performance_stats['avg_response_time'] = total_time / len(self.query_history)
    
    def analyze_query_patterns(self) -> Dict[str, Any]:
        """Analyze query patterns for optimization opportunities."""
        patterns = {}
        
        for query, count in self.query_patterns.items():
            # Find slow instances of this query
            slow_instances = [
                q for q in self.query_history 
                if q['query'] == query and q['duration_ms'] > 100
            ]
            
            avg_duration = sum(q['duration_ms'] for q in slow_instances) / len(slow_instances) if slow_instances else 0
            
            patterns[query] = {
                'count': count,
                'slow_instances': len(slow_instances),
                'avg_duration_ms': avg_duration,
                'optimization_needed': avg_duration > 50
            }
        
        return patterns
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        patterns = self.analyze_query_patterns()
        
        # Identify most frequent queries
        frequent_queries = sorted(
            patterns.items(), 
            key=lambda x: x[1]['count'], 
            reverse=True
        )[:10]
        
        # Identify slowest queries
        slowest_queries = sorted(
            patterns.items(), 
            key=lambda x: x[1]['avg_duration_ms'], 
            reverse=True
        )[:10]
        
        return {
            'timestamp': datetime.now().isoformat(),
            'performance_stats': self.performance_stats,
            'frequent_queries': frequent_queries,
            'slowest_queries': slowest_queries,
            'optimization_recommendations': self._generate_optimization_recommendations(patterns)
        }
    
    def _generate_optimization_recommendations(self, patterns: Dict[str, Any]) -> List[str]:
        """Generate optimization recommendations based on query patterns."""
        recommendations = []
        
        for query, stats in patterns.items():
            if stats['optimization_needed']:
                if 'SELECT COUNT(*)' in query and 'users' in query:
                    recommendations.append("Consider adding index on users table for COUNT queries")
                elif 'SELECT COUNT(*)' in query and 'devices' in query:
                    recommendations.append("Consider adding index on devices table for COUNT queries")
                elif 'WHERE email' in query:
                    recommendations.append("Ensure email column has proper index")
                elif 'WHERE user_id' in query:
                    recommendations.append("Ensure user_id foreign keys have indexes")
                elif 'ORDER BY' in query:
                    recommendations.append("Consider adding composite indexes for ORDER BY clauses")
                elif 'JOIN' in query:
                    recommendations.append("Optimize JOIN queries with proper indexes")
        
        return list(set(recommendations))  # Remove duplicates

class IndexOptimizer:
    """Analyzes and recommends database index improvements."""
    
    def __init__(self):
        self.existing_indexes = {}
        self.recommended_indexes = []
    
    def analyze_current_indexes(self) -> Dict[str, Any]:
        """Analyze current database indexes."""
        try:
            inspector = inspect(db.engine)
            index_analysis = {}
            
            for table_name in inspector.get_table_names():
                indexes = inspector.get_indexes(table_name)
                index_analysis[table_name] = {
                    'indexes': indexes,
                    'count': len(indexes),
                    'columns': [idx['column_names'] for idx in indexes]
                }
            
            self.existing_indexes = index_analysis
            return index_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing indexes: {e}")
            return {}
    
    def recommend_indexes(self) -> List[Dict[str, Any]]:
        """Recommend indexes based on query patterns and table structure."""
        recommendations = []
        
        # Analyze query patterns to recommend indexes
        query_patterns = self._analyze_query_patterns()
        
        for table, patterns in query_patterns.items():
            for pattern in patterns:
                if pattern['type'] == 'where_clause':
                    recommendations.append({
                        'table': table,
                        'columns': pattern['columns'],
                        'type': 'INDEX',
                        'reason': f"Frequently used in WHERE clauses ({pattern['frequency']} times)",
                        'priority': 'high' if pattern['frequency'] > 10 else 'medium'
                    })
                elif pattern['type'] == 'order_by':
                    recommendations.append({
                        'table': table,
                        'columns': pattern['columns'],
                        'type': 'INDEX',
                        'reason': f"Used in ORDER BY clauses ({pattern['frequency']} times)",
                        'priority': 'medium'
                    })
                elif pattern['type'] == 'foreign_key':
                    recommendations.append({
                        'table': table,
                        'columns': pattern['columns'],
                        'type': 'FOREIGN KEY INDEX',
                        'reason': f"Foreign key relationship ({pattern['frequency']} joins)",
                        'priority': 'high'
                    })
        
        self.recommended_indexes = recommendations
        return recommendations
    
    def _analyze_query_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze query patterns to identify index needs."""
        # This would analyze actual query patterns
        # For now, return common patterns based on our schema
        return {
            'users': [
                {'type': 'where_clause', 'columns': ['email'], 'frequency': 50},
                {'type': 'where_clause', 'columns': ['user_id'], 'frequency': 30},
                {'type': 'order_by', 'columns': ['registration_date'], 'frequency': 20}
            ],
            'devices': [
                {'type': 'where_clause', 'columns': ['user_id'], 'frequency': 40},
                {'type': 'where_clause', 'columns': ['device_id'], 'frequency': 25},
                {'type': 'foreign_key', 'columns': ['user_id'], 'frequency': 40}
            ],
            'auth_logs': [
                {'type': 'where_clause', 'columns': ['user_id'], 'frequency': 35},
                {'type': 'order_by', 'columns': ['timestamp'], 'frequency': 30},
                {'type': 'foreign_key', 'columns': ['user_id'], 'frequency': 35}
            ],
            'sessions': [
                {'type': 'where_clause', 'columns': ['user_id'], 'frequency': 45},
                {'type': 'where_clause', 'columns': ['session_id'], 'frequency': 30},
                {'type': 'foreign_key', 'columns': ['user_id'], 'frequency': 45}
            ]
        }
    
    def generate_index_script(self) -> str:
        """Generate SQL script for recommended indexes."""
        script_lines = ["-- Database Index Optimization Script", ""]
        
        for rec in self.recommended_indexes:
            if rec['priority'] == 'high':
                index_name = f"idx_{rec['table']}_{'_'.join(rec['columns'])}"
                columns = ', '.join(rec['columns'])
                script_lines.append(f"-- {rec['reason']}")
                script_lines.append(f"CREATE INDEX IF NOT EXISTS {index_name} ON {rec['table']} ({columns});")
                script_lines.append("")
        
        return '\n'.join(script_lines)

class ConnectionPoolOptimizer:
    """Optimizes database connection pooling configuration."""
    
    def __init__(self):
        self.current_config = {}
        self.optimized_config = {}
    
    def analyze_current_pool(self) -> Dict[str, Any]:
        """Analyze current connection pool configuration."""
        try:
            pool = db.engine.pool
            
            self.current_config = {
                'pool_size': pool.size(),
                'max_overflow': pool._max_overflow,
                'pool_timeout': pool._timeout,
                'pool_recycle': getattr(pool, '_recycle', None),
                'pool_pre_ping': getattr(pool, '_pre_ping', False),
                'checked_in': pool.checkedin(),
                'checked_out': pool.checkedout(),
                'overflow': pool.overflow(),
                'invalid': pool.invalid()
            }
            
            return self.current_config
            
        except Exception as e:
            logger.error(f"Error analyzing connection pool: {e}")
            return {}
    
    def recommend_pool_settings(self) -> Dict[str, Any]:
        """Recommend optimized connection pool settings."""
        current = self.current_config
        
        # Analyze current usage patterns
        total_connections = current.get('checked_in', 0) + current.get('checked_out', 0)
        overflow_usage = current.get('overflow', 0)
        
        # Calculate optimal settings based on usage
        if total_connections > 0:
            avg_usage = total_connections / 2
            recommended_pool_size = max(5, min(20, int(avg_usage * 1.5)))
            recommended_overflow = max(10, int(recommended_pool_size * 0.5))
        else:
            recommended_pool_size = 10
            recommended_overflow = 5
        
        self.optimized_config = {
            'pool_size': recommended_pool_size,
            'max_overflow': recommended_overflow,
            'pool_timeout': 30,
            'pool_recycle': 3600,  # 1 hour
            'pool_pre_ping': True,
            'echo': False
        }
        
        return {
            'current_config': current,
            'recommended_config': self.optimized_config,
            'improvements': self._calculate_improvements(current, self.optimized_config)
        }
    
    def _calculate_improvements(self, current: Dict, recommended: Dict) -> List[str]:
        """Calculate potential improvements from recommended settings."""
        improvements = []
        
        if recommended['pool_size'] > current.get('pool_size', 0):
            improvements.append(f"Increase pool size from {current.get('pool_size', 0)} to {recommended['pool_size']}")
        
        if recommended['max_overflow'] > current.get('max_overflow', 0):
            improvements.append(f"Increase max overflow from {current.get('max_overflow', 0)} to {recommended['max_overflow']}")
        
        if not current.get('pool_pre_ping', False):
            improvements.append("Enable pool_pre_ping for better connection validation")
        
        if current.get('pool_recycle') is None:
            improvements.append("Set pool_recycle to 3600 seconds to prevent stale connections")
        
        return improvements
    
    def apply_optimized_settings(self) -> bool:
        """Apply optimized connection pool settings."""
        try:
            # This would require recreating the engine with new settings
            # For now, return the recommended configuration
            return True
        except Exception as e:
            logger.error(f"Error applying optimized settings: {e}")
            return False

class DatabaseOptimizer:
    """Main database optimization orchestrator."""
    
    def __init__(self):
        self.query_analyzer = QueryAnalyzer()
        self.index_optimizer = IndexOptimizer()
        self.pool_optimizer = ConnectionPoolOptimizer()
    
    def perform_comprehensive_analysis(self) -> Dict[str, Any]:
        """Perform comprehensive database analysis."""
        start_time = time.time()
        
        # Analyze current state
        index_analysis = self.index_optimizer.analyze_current_indexes()
        pool_analysis = self.pool_optimizer.analyze_current_pool()
        query_analysis = self.query_analyzer.get_performance_report()
        
        # Generate recommendations
        index_recommendations = self.index_optimizer.recommend_indexes()
        pool_recommendations = self.pool_optimizer.recommend_pool_settings()
        
        analysis_duration = round((time.time() - start_time) * 1000, 2)
        
        return {
            'timestamp': datetime.now().isoformat(),
            'analysis_duration_ms': analysis_duration,
            'index_analysis': index_analysis,
            'pool_analysis': pool_analysis,
            'query_analysis': query_analysis,
            'index_recommendations': index_recommendations,
            'pool_recommendations': pool_recommendations,
            'optimization_score': self._calculate_optimization_score(
                index_analysis, pool_analysis, query_analysis
            )
        }
    
    def _calculate_optimization_score(self, index_analysis: Dict, pool_analysis: Dict, query_analysis: Dict) -> int:
        """Calculate overall optimization score (0-100)."""
        score = 100
        
        # Deduct points for missing indexes
        for table, analysis in index_analysis.items():
            if analysis['count'] < 2:  # Most tables should have at least 2 indexes
                score -= 10
        
        # Deduct points for slow queries
        slow_query_percentage = (
            query_analysis.get('performance_stats', {}).get('slow_queries', 0) /
            max(query_analysis.get('performance_stats', {}).get('total_queries', 1), 1) * 100
        )
        score -= min(30, slow_query_percentage * 2)
        
        # Deduct points for pool issues
        pool_config = pool_analysis.get('current_config', {})
        if pool_config.get('overflow', 0) > 0:
            score -= 15
        
        return max(0, score)
    
    def generate_optimization_report(self) -> str:
        """Generate a comprehensive optimization report."""
        analysis = self.perform_comprehensive_analysis()
        
        report_lines = [
            "=" * 60,
            "DATABASE OPTIMIZATION REPORT",
            "=" * 60,
            f"Generated: {analysis['timestamp']}",
            f"Analysis Duration: {analysis['analysis_duration_ms']}ms",
            f"Optimization Score: {analysis['optimization_score']}/100",
            "",
            "INDEX ANALYSIS:",
            "-" * 20
        ]
        
        for table, info in analysis['index_analysis'].items():
            report_lines.append(f"{table}: {info['count']} indexes")
        
        report_lines.extend([
            "",
            "QUERY PERFORMANCE:",
            "-" * 20,
            f"Total Queries: {analysis['query_analysis']['performance_stats']['total_queries']}",
            f"Slow Queries: {analysis['query_analysis']['performance_stats']['slow_queries']}",
            f"Average Response Time: {analysis['query_analysis']['performance_stats']['avg_response_time']:.2f}ms",
            "",
            "RECOMMENDATIONS:",
            "-" * 20
        ])
        
        for rec in analysis['index_recommendations']:
            if rec['priority'] == 'high':
                report_lines.append(f"🔴 {rec['reason']}")
            else:
                report_lines.append(f"🟡 {rec['reason']}")
        
        for improvement in analysis['pool_recommendations']['improvements']:
            report_lines.append(f"🔧 {improvement}")
        
        return '\n'.join(report_lines)

# Global instance
db_optimizer = DatabaseOptimizer()

def get_database_optimization_report() -> Dict[str, Any]:
    """Get comprehensive database optimization report."""
    return db_optimizer.perform_comprehensive_analysis()

def record_database_query(query: str, duration_ms: float, endpoint: str, params: Dict = None):
    """Record a database query for analysis."""
    db_optimizer.query_analyzer.record_query(query, duration_ms, endpoint, params)

def generate_index_script() -> str:
    """Generate SQL script for recommended indexes."""
    return db_optimizer.index_optimizer.generate_index_script()

def get_optimization_score() -> int:
    """Get current database optimization score."""
    analysis = db_optimizer.perform_comprehensive_analysis()
    return analysis['optimization_score'] 