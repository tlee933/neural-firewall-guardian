#!/usr/bin/env python3
"""
AI Suricata - Intelligent Threat Detection and Response System
Integrates alert collection, ML classification, and automated response
"""

import sys
import argparse
import signal
import time
from datetime import datetime
from alert_collector import SuricataAlertCollector
from ml_classifier import ThreatClassifier
from auto_responder import AutoResponder
from prometheus_exporter import PrometheusExporter
from training_data_collector import TrainingDataCollector

class AISuricata:
    def __init__(self, pfsense_host="192.168.1.1", pfsense_user="admin", dry_run=False, auto_block=False, prometheus_port=9102):
        print("[*] Initializing AI Suricata System...")

        self.collector = SuricataAlertCollector(pfsense_host, pfsense_user)
        self.classifier = ThreatClassifier()
        self.responder = AutoResponder(pfsense_host, pfsense_user, dry_run=dry_run)

        self.auto_block = auto_block
        self.running = True

        # Statistics
        self.processed_count = 0
        self.threat_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        # Prometheus exporter
        self.exporter = PrometheusExporter(port=prometheus_port)
        self.exporter.start()

        # Training data collector (for future supervised learning)
        self.data_collector = TrainingDataCollector(enabled=True)

        # Load pre-trained models if available
        if self.classifier.load_models():
            print("[+] Loaded pre-trained ML models")
        else:
            print("[*] No pre-trained models found - will train on incoming data")

        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print("\n\n[*] Shutting down AI Suricata...")
        self.running = False
        self.print_final_summary()
        sys.exit(0)

    def train_on_historical_data(self, num_events=5000):
        """Train models on historical alert data"""
        print(f"[*] Training on historical data ({num_events} events)...")

        feature_vectors = []
        alert_count = 0

        for line in self.collector.tail_eve_log(follow=False, lines=num_events):
            event = self.collector.parse_event(line)
            if not event or event.get("event_type") != "alert":
                continue

            alert_data = self.collector.process_alert(event)
            if alert_data:
                # Extract features for ML training
                features = self.classifier.extract_ml_features(alert_data)
                feature_vectors.append(features)
                alert_count += 1

        if feature_vectors:
            print(f"[+] Extracted {len(feature_vectors)} feature vectors from {alert_count} alerts")
            self.classifier.train_anomaly_detector(feature_vectors)
            self.classifier.save_models()
        else:
            print("[!] No alerts found in historical data")

    def process_alert(self, event):
        """Process a single alert through the full pipeline"""
        start_time = time.time()

        # Step 1: Collect and extract features
        alert_data = self.collector.process_alert(event)
        if not alert_data:
            return None

        self.processed_count += 1
        features = alert_data["features"]

        # Step 2: ML classification
        classification = self.classifier.classify_threat(alert_data)

        # Update statistics
        self.threat_count[classification["severity"]] += 1

        # Log classification for training data collection
        feature_vector = self.classifier.extract_ml_features(alert_data)
        self.data_collector.log_classification(
            alert_data=alert_data,
            classification=classification,
            features_vector=feature_vector.tolist() if hasattr(feature_vector, 'tolist') else feature_vector
        )

        # Record metrics to Prometheus
        processing_time = time.time() - start_time
        self.exporter.metrics.record_alert(
            severity=classification["severity"],
            action=classification["action"],
            source_ip=features["src_ip"],
            signature=features["signature"][:80],  # Truncate long signatures
            threat_score=classification["threat_score"],
            processing_time=processing_time
        )
        self.exporter.metrics.record_training_example()

        # Step 3: Display alert
        self.display_alert(alert_data, classification)

        # Step 4: Automated response (if enabled)
        if self.auto_block:
            if classification["action"] in ["BLOCK", "RATE_LIMIT"]:
                # Confirm before blocking
                if classification["severity"] == "CRITICAL":
                    print(f"    [!] AUTO-BLOCKING {features['src_ip']} due to CRITICAL threat")
                    result = self.responder.execute_action(alert_data, classification)
                    print(f"    [+] Action result: {result}")
                    if classification["action"] == "BLOCK":
                        self.exporter.metrics.record_block()
                    elif classification["action"] == "RATE_LIMIT":
                        self.exporter.metrics.record_rate_limit()
                else:
                    print(f"    [*] Action recommended: {classification['action']} (not auto-executing)")
            elif classification["action"] == "MONITOR":
                self.responder.monitor_ip(features["src_ip"], alert_data)

        return classification

    def display_alert(self, alert_data, classification):
        """Display formatted alert with classification"""
        f = alert_data["features"]
        c = classification

        timestamp = datetime.now().strftime("%H:%M:%S")

        # Color coding based on severity
        colors = {
            "CRITICAL": "\033[91m\033[1m",  # Bold red
            "HIGH": "\033[91m",             # Red
            "MEDIUM": "\033[93m",           # Yellow
            "LOW": "\033[96m",              # Cyan
            "INFO": "\033[90m"              # Gray
        }
        reset = "\033[0m"

        color = colors.get(c["severity"], "")

        # Main alert line
        output = (
            f"{color}[{timestamp}] [{c['severity']:8s}] "
            f"{f['src_ip']:15s} → {f['dest_ip']:15s}:{f['dest_port']:5d} | "
            f"Score: {c['threat_score']:.2f} | "
            f"Action: {c['action']:12s}"
        )

        # Add signature
        output += f"\n    └─ {f['signature'][:80]}"

        # Add patterns if detected
        if c.get("attack_patterns"):
            patterns_str = ", ".join([
                f"{p['pattern']} ({p['confidence']:.0%})"
                for p in c["attack_patterns"]
            ])
            output += f"\n    └─ Patterns: {patterns_str}"

        # Add recommendation
        if c.get("recommendation"):
            output += f"\n    └─ {c['recommendation']}"

        output += reset
        print(output)

    def monitor_live(self):
        """Start live monitoring and threat response"""
        print("\n" + "="*80)
        print("AI SURICATA - LIVE MONITORING")
        print("="*80)
        print(f"Auto-blocking: {'ENABLED' if self.auto_block else 'DISABLED'}")
        print(f"Dry-run mode: {'YES' if self.responder.dry_run else 'NO'}")
        print("Press Ctrl+C to stop\n")

        try:
            for line in self.collector.tail_eve_log(follow=True):
                if not self.running:
                    break

                event = self.collector.parse_event(line)
                if event and event.get("event_type") == "alert":
                    # Skip checksum errors early (hardware offload false positives)
                    signature = event.get("alert", {}).get("signature", "").lower()
                    if "checksum" in signature or "invalid ack" in signature:
                        continue

                    self.process_alert(event)

                # Periodic cleanup
                if self.processed_count % 1000 == 0 and self.processed_count > 0:
                    self.responder.cleanup_old_blocks(max_age_hours=24)

        except KeyboardInterrupt:
            pass

    def print_final_summary(self):
        """Print final statistics"""
        print("\n" + "="*80)
        print("AI SURICATA - SESSION SUMMARY")
        print("="*80)
        print(f"Total Alerts Processed: {self.processed_count}")
        print(f"\nThreat Distribution:")
        for severity, count in sorted(self.threat_count.items(), key=lambda x: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(x[0])):
            pct = (count / max(self.processed_count, 1)) * 100
            print(f"  {severity:8s}: {count:5d} ({pct:5.1f}%)")

        print()
        self.responder.print_stats()
        self.collector.print_summary()

def main():
    parser = argparse.ArgumentParser(description="AI Suricata - Intelligent Threat Detection")
    parser.add_argument("--host", default="192.168.1.1", help="pfSense host")
    parser.add_argument("--user", default="admin", help="pfSense SSH user")
    parser.add_argument("--train", action="store_true", help="Train on historical data first")
    parser.add_argument("--auto-block", action="store_true", help="Enable automatic blocking")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode (no actual blocking)")
    parser.add_argument("--events", type=int, default=5000, help="Number of historical events for training")

    args = parser.parse_args()

    # Initialize system
    ai_suricata = AISuricata(
        pfsense_host=args.host,
        pfsense_user=args.user,
        dry_run=args.dry_run,
        auto_block=args.auto_block
    )

    # Train on historical data if requested
    if args.train:
        ai_suricata.train_on_historical_data(num_events=args.events)
        print()

    # Start live monitoring
    ai_suricata.monitor_live()

if __name__ == "__main__":
    main()
