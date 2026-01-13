"""
Simple HTTP server for health checks and metrics.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import structlog

from src.utils.metrics import get_metrics_text, get_metrics_content_type
from src.utils.health import HealthChecker

logger = structlog.get_logger()


class HealthMetricsHandler(BaseHTTPRequestHandler):
    """HTTP request handler for health and metrics endpoints."""
    
    # Class variables to be set by server
    health_checker: HealthChecker = None
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == '/health':
            self._handle_health()
        elif self.path == '/metrics':
            self._handle_metrics()
        elif self.path == '/':
            self._handle_root()
        else:
            self.send_error(404, 'Not Found')
    
    def _handle_health(self):
        """Handle health check endpoint."""
        try:
            health_status = self.health_checker.check_health()
            
            # Set response code based on health
            status_code = 200 if health_status['status'] == 'healthy' else 503
            
            self.send_response(status_code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            self.wfile.write(json.dumps(health_status, indent=2).encode())
        except Exception as e:
            logger.error("health_check_error", error=str(e))
            self.send_error(500, f'Health check failed: {str(e)}')
    
    def _handle_metrics(self):
        """Handle Prometheus metrics endpoint."""
        try:
            metrics_text = get_metrics_text()
            
            self.send_response(200)
            self.send_header('Content-Type', get_metrics_content_type())
            self.end_headers()
            
            self.wfile.write(metrics_text)
        except Exception as e:
            logger.error("metrics_error", error=str(e))
            self.send_error(500, f'Metrics generation failed: {str(e)}')
    
    def _handle_root(self):
        """Handle root endpoint."""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Exposure Ingestion Service</title>
        </head>
        <body>
            <h1>Exposure Ingestion Service</h1>
            <ul>
                <li><a href="/health">Health Check</a></li>
                <li><a href="/metrics">Prometheus Metrics</a></li>
            </ul>
        </body>
        </html>
        """
        self.wfile.write(html.encode())
    
    def log_message(self, format, *args):
        """Override to use structured logging."""
        logger.debug("http_request", path=self.path, method=self.command)


class HealthMetricsServer:
    """HTTP server for health checks and metrics."""
    
    def __init__(self, health_checker: HealthChecker, host: str = '0.0.0.0', port: int = 8000):
        self.health_checker = health_checker
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
    
    def start(self):
        """Start the HTTP server in a background thread."""
        # Set health checker on handler class
        HealthMetricsHandler.health_checker = self.health_checker
        
        # Create server
        self.server = HTTPServer((self.host, self.port), HealthMetricsHandler)
        
        # Start in background thread
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        
        logger.info("health_metrics_server_started", host=self.host, port=self.port)
    
    def stop(self):
        """Stop the HTTP server."""
        if self.server:
            self.server.shutdown()
            logger.info("health_metrics_server_stopped")
