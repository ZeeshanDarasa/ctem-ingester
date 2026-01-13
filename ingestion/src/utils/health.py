"""
Health check endpoint and utilities.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any
from sqlalchemy.exc import SQLAlchemyError

from src.storage.connection import DatabaseManager


class HealthChecker:
    """Performs health checks for the ingestion service."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db_manager = db_manager
    
    def check_health(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check.
        
        Returns:
            Dict with health status and details
        """
        checks = {
            'database': self._check_database(),
            'filesystem': self._check_filesystem(),
            'service': self._check_service()
        }
        
        # Overall status: healthy if all checks pass
        all_healthy = all(check['status'] == 'healthy' for check in checks.values())
        
        return {
            'status': 'healthy' if all_healthy else 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'checks': checks
        }
    
    def _check_database(self) -> Dict[str, Any]:
        """Check database connectivity."""
        try:
            # Try to execute a simple query
            session = self.db_manager.get_session()
            session.execute('SELECT 1')
            session.close()
            
            return {
                'status': 'healthy',
                'message': 'Database connection OK'
            }
        except SQLAlchemyError as e:
            return {
                'status': 'unhealthy',
                'message': f'Database error: {str(e)}'
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'message': f'Unexpected error: {str(e)}'
            }
    
    def _check_filesystem(self) -> Dict[str, Any]:
        """Check required directories are accessible."""
        watch_dir = Path(os.getenv('WATCH_DIR', '/data/scan_results'))
        processed_dir = Path(os.getenv('PROCESSED_DIR', '/data/processed'))
        quarantine_dir = Path(os.getenv('QUARANTINE_DIR', '/data/quarantine'))
        
        issues = []
        
        for dir_path, name in [
            (watch_dir, 'watch_dir'),
            (processed_dir, 'processed_dir'),
            (quarantine_dir, 'quarantine_dir')
        ]:
            if not dir_path.exists():
                issues.append(f'{name} does not exist: {dir_path}')
            elif not os.access(dir_path, os.R_OK | os.W_OK):
                issues.append(f'{name} not readable/writable: {dir_path}')
        
        if issues:
            return {
                'status': 'unhealthy',
                'message': '; '.join(issues)
            }
        
        return {
            'status': 'healthy',
            'message': 'All directories accessible'
        }
    
    def _check_service(self) -> Dict[str, Any]:
        """Check service configuration."""
        required_env = ['WATCH_DIR', 'DB_PATH']
        missing = [env for env in required_env if not os.getenv(env)]
        
        if missing:
            return {
                'status': 'unhealthy',
                'message': f'Missing environment variables: {", ".join(missing)}'
            }
        
        return {
            'status': 'healthy',
            'message': 'Service configuration OK'
        }
