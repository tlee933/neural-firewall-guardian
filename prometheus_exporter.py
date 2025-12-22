#!/usr/bin/env python3
"""
Prometheus Exporter for AI Suricata
Exposes metrics for threat detection, blocking, and system health
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread, Lock
from collections import defaultdict
import time

class SuricataMetrics:
    """Thread-safe metrics storage for AI Suricata"""

    def __init__(self):
        self.lock = Lock()
        self.start_time = time.time()

        # Alert counters
        self.total_alerts = 0
        self.alerts_by_severity = defaultdict(int)
        self.alerts_by_action = defaultdict(int)

        # Blocking stats
        self.total_blocks = 0
        self.total_rate_limits = 0
        self.active_blocks = 0

        # IP tracking
        self.top_source_ips = defaultdict(int)
        self.top_signatures = defaultdict(int)

        # Performance
        self.processing_time_sum = 0.0
        self.processing_count = 0

        # Threat scores
        self.threat_score_sum = 0.0
        self.critical_threats = 0
        self.high_threats = 0

    def record_alert(self, severity, action, source_ip, signature, threat_score, processing_time=0.0):
        """Record an alert with all its metadata"""
        with self.lock:
            self.total_alerts += 1
            self.alerts_by_severity[severity] += 1
            self.alerts_by_action[action] += 1
            self.top_source_ips[source_ip] += 1
            self.top_signatures[signature] += 1
            self.threat_score_sum += threat_score
            self.processing_time_sum += processing_time
            self.processing_count += 1

            if severity == "CRITICAL":
                self.critical_threats += 1
            elif severity == "HIGH":
                self.high_threats += 1

    def record_block(self):
        """Record a blocked IP"""
        with self.lock:
            self.total_blocks += 1
            self.active_blocks += 1

    def record_unblock(self):
        """Record an unblocked IP"""
        with self.lock:
            self.active_blocks = max(0, self.active_blocks - 1)

    def record_rate_limit(self):
        """Record a rate-limited IP"""
        with self.lock:
            self.total_rate_limits += 1

    def get_prometheus_metrics(self):
        """Generate Prometheus-formatted metrics"""
        with self.lock:
            uptime = time.time() - self.start_time
            avg_processing_time = self.processing_time_sum / max(1, self.processing_count)
            avg_threat_score = self.threat_score_sum / max(1, self.total_alerts)

            metrics = []

            # Basic info
            metrics.append('# HELP suricata_ai_uptime_seconds Uptime of AI Suricata service')
            metrics.append('# TYPE suricata_ai_uptime_seconds gauge')
            metrics.append(f'suricata_ai_uptime_seconds {uptime:.2f}')

            # Total alerts
            metrics.append('# HELP suricata_ai_alerts_total Total number of alerts processed')
            metrics.append('# TYPE suricata_ai_alerts_total counter')
            metrics.append(f'suricata_ai_alerts_total {self.total_alerts}')

            # Alerts by severity
            metrics.append('# HELP suricata_ai_alerts_by_severity_total Alerts by severity level')
            metrics.append('# TYPE suricata_ai_alerts_by_severity_total counter')
            for severity, count in self.alerts_by_severity.items():
                metrics.append(f'suricata_ai_alerts_by_severity_total{{severity="{severity}"}} {count}')

            # Alerts by action
            metrics.append('# HELP suricata_ai_alerts_by_action_total Alerts by recommended action')
            metrics.append('# TYPE suricata_ai_alerts_by_action_total counter')
            for action, count in self.alerts_by_action.items():
                metrics.append(f'suricata_ai_alerts_by_action_total{{action="{action}"}} {count}')

            # Blocking stats
            metrics.append('# HELP suricata_ai_blocks_total Total IPs blocked')
            metrics.append('# TYPE suricata_ai_blocks_total counter')
            metrics.append(f'suricata_ai_blocks_total {self.total_blocks}')

            metrics.append('# HELP suricata_ai_active_blocks Currently active blocks')
            metrics.append('# TYPE suricata_ai_active_blocks gauge')
            metrics.append(f'suricata_ai_active_blocks {self.active_blocks}')

            metrics.append('# HELP suricata_ai_rate_limits_total Total IPs rate-limited')
            metrics.append('# TYPE suricata_ai_rate_limits_total counter')
            metrics.append(f'suricata_ai_rate_limits_total {self.total_rate_limits}')

            # Threat metrics
            metrics.append('# HELP suricata_ai_critical_threats_total Critical threats detected')
            metrics.append('# TYPE suricata_ai_critical_threats_total counter')
            metrics.append(f'suricata_ai_critical_threats_total {self.critical_threats}')

            metrics.append('# HELP suricata_ai_high_threats_total High severity threats detected')
            metrics.append('# TYPE suricata_ai_high_threats_total counter')
            metrics.append(f'suricata_ai_high_threats_total {self.high_threats}')

            # Average scores
            metrics.append('# HELP suricata_ai_avg_threat_score Average threat score')
            metrics.append('# TYPE suricata_ai_avg_threat_score gauge')
            metrics.append(f'suricata_ai_avg_threat_score {avg_threat_score:.3f}')

            # Performance
            metrics.append('# HELP suricata_ai_processing_time_seconds Average alert processing time')
            metrics.append('# TYPE suricata_ai_processing_time_seconds gauge')
            metrics.append(f'suricata_ai_processing_time_seconds {avg_processing_time:.6f}')

            metrics.append('# HELP suricata_ai_alerts_per_second Current alert rate')
            metrics.append('# TYPE suricata_ai_alerts_per_second gauge')
            rate = self.total_alerts / max(1, uptime)
            metrics.append(f'suricata_ai_alerts_per_second {rate:.2f}')

            # Top source IPs (top 10)
            metrics.append('# HELP suricata_ai_top_source_ips Alerts by source IP')
            metrics.append('# TYPE suricata_ai_top_source_ips gauge')
            for ip, count in sorted(self.top_source_ips.items(), key=lambda x: x[1], reverse=True)[:10]:
                metrics.append(f'suricata_ai_top_source_ips{{source_ip="{ip}"}} {count}')

            return '\n'.join(metrics) + '\n'

class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for Prometheus metrics endpoint"""

    metrics_store = None  # Will be set by PrometheusExporter

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/metrics':
            metrics = self.metrics_store.get_prometheus_metrics()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(metrics.encode('utf-8'))
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK\n')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress request logging"""
        pass

class PrometheusExporter:
    """Prometheus metrics exporter for AI Suricata"""

    def __init__(self, port=9102):
        self.port = port
        self.metrics = SuricataMetrics()
        self.server = None
        self.thread = None

        # Set metrics store for handler
        MetricsHandler.metrics_store = self.metrics

    def start(self):
        """Start the metrics HTTP server in a background thread"""
        self.server = HTTPServer(('0.0.0.0', self.port), MetricsHandler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        print(f"[*] Prometheus exporter started on http://0.0.0.0:{self.port}/metrics")

    def stop(self):
        """Stop the metrics HTTP server"""
        if self.server:
            self.server.shutdown()
            self.thread.join()

if __name__ == "__main__":
    # Test the exporter
    exporter = PrometheusExporter(port=9101)
    exporter.start()

    # Simulate some metrics
    import random
    print("[*] Simulating metrics for testing...")
    for i in range(100):
        severity = random.choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        action = random.choice(["BLOCK", "RATE_LIMIT", "MONITOR", "LOG", "IGNORE"])
        ip = f"192.168.1.{random.randint(10, 250)}"
        signature = random.choice(["Port Scan", "DoS Attack", "Brute Force", "Malware", "Suspicious Traffic"])
        score = random.random()

        exporter.metrics.record_alert(severity, action, ip, signature, score, random.random() * 0.001)

        if action == "BLOCK":
            exporter.metrics.record_block()
        elif action == "RATE_LIMIT":
            exporter.metrics.record_rate_limit()

    print(f"[*] Test metrics available at http://localhost:9101/metrics")
    print("[*] Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping exporter...")
        exporter.stop()
