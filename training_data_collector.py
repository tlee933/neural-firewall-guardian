#!/usr/bin/env python3
"""
Training Data Collector
Logs ML classification decisions for future supervised learning
"""

import json
import os
from datetime import datetime
from pathlib import Path


class TrainingDataCollector:
    """Collects classification decisions for building supervised learning datasets"""

    def __init__(self, data_dir="/home/hashcat/pfsense/ai_suricata/training_data", enabled=True):
        self.data_dir = Path(data_dir)
        self.enabled = enabled
        self.examples_collected = 0

        if self.enabled:
            self.data_dir.mkdir(parents=True, exist_ok=True)
            print(f"[+] Training data collection enabled: {self.data_dir}")

    def get_current_log_file(self):
        """Get log file path for today (daily rotation)"""
        date_str = datetime.now().strftime("%Y-%m-%d")
        return self.data_dir / f"decisions.{date_str}.jsonl"

    def log_classification(self, alert_data, classification, features_vector):
        """
        Log a classification decision for future training

        Args:
            alert_data: Original alert dict from Suricata
            classification: ML classification result dict
            features_vector: Extracted feature vector (16 dimensions)
        """
        if not self.enabled:
            return

        try:
            # Build training example
            example = {
                # Timestamp
                "timestamp": alert_data.get("timestamp", datetime.now().isoformat()),

                # Alert metadata
                "source_ip": alert_data.get("src_ip", "unknown"),
                "dest_ip": alert_data.get("dest_ip", "unknown"),
                "signature": alert_data.get("alert", {}).get("signature", ""),
                "signature_id": alert_data.get("alert", {}).get("signature_id", 0),
                "category": alert_data.get("alert", {}).get("category", ""),

                # Feature vector (16 dimensions)
                "features": {
                    "severity": features_vector[0] if len(features_vector) > 0 else 0,
                    "src_port": features_vector[1] if len(features_vector) > 1 else 0,
                    "dest_port": features_vector[2] if len(features_vector) > 2 else 0,
                    "packets_toserver": features_vector[3] if len(features_vector) > 3 else 0,
                    "packets_toclient": features_vector[4] if len(features_vector) > 4 else 0,
                    "bytes_toserver": features_vector[5] if len(features_vector) > 5 else 0,
                    "bytes_toclient": features_vector[6] if len(features_vector) > 6 else 0,
                    "avg_pkt_size_toserver": features_vector[7] if len(features_vector) > 7 else 0,
                    "avg_pkt_size_toclient": features_vector[8] if len(features_vector) > 8 else 0,
                    "ip_alert_count": features_vector[9] if len(features_vector) > 9 else 0,
                    "ip_unique_sigs": features_vector[10] if len(features_vector) > 10 else 0,
                    "is_tcp": features_vector[11] if len(features_vector) > 11 else 0,
                    "is_udp": features_vector[12] if len(features_vector) > 12 else 0,
                    "is_icmp": features_vector[13] if len(features_vector) > 13 else 0,
                    "is_auth_port": features_vector[14] if len(features_vector) > 14 else 0,
                    "is_web_port": features_vector[15] if len(features_vector) > 15 else 0,
                },

                # ML classification decision
                "classification": {
                    "base_score": classification.get("base_score", 0.0),
                    "anomaly_score": classification.get("anomaly_score", 0.0),
                    "pattern_score": classification.get("pattern_score", 0.0),
                    "threat_score": classification.get("threat_score", 0.0),
                    "severity": classification.get("severity", "UNKNOWN"),
                    "action": classification.get("action", "LOG"),
                    "patterns_detected": classification.get("patterns_detected", [])
                },

                # User feedback (to be added later via review tool)
                "label": None,  # Will be: "THREAT" | "BENIGN" | "FALSE_POSITIVE"
                "labeled_by": None,
                "labeled_at": None,
                "notes": None,

                # Auto-labeling hints (heuristics)
                "auto_label_hint": self._get_auto_label_hint(alert_data, classification)
            }

            # Append to JSONL file (one JSON object per line)
            log_file = self.get_current_log_file()
            with open(log_file, 'a') as f:
                f.write(json.dumps(example) + '\n')

            self.examples_collected += 1

        except Exception as e:
            # Don't crash the main processing loop if logging fails
            print(f"[!] Warning: Failed to log training example: {e}")

    def _get_auto_label_hint(self, alert_data, classification):
        """
        Generate automatic labeling hint based on heuristics
        This helps reduce manual labeling effort

        Returns:
            str: "BENIGN" | "THREAT" | "REVIEW" (needs manual review)
        """
        signature = alert_data.get("alert", {}).get("signature", "").lower()
        action = classification.get("action", "LOG")
        threat_score = classification.get("threat_score", 0.0)

        # Auto-label as BENIGN
        benign_patterns = [
            "checksum",
            "invalid ack",
            "packet out of window",
            "stream established",
            "invalid timestamp"
        ]

        if any(pattern in signature for pattern in benign_patterns):
            return "BENIGN"

        # Auto-label as THREAT (high confidence blocks)
        if action == "BLOCK" and threat_score >= 0.90:
            return "THREAT"

        # Auto-label known exploit signatures as THREAT
        if "exploit" in signature or "malware" in signature or "trojan" in signature:
            return "THREAT"

        # Everything else needs manual review
        return "REVIEW"

    def get_stats(self):
        """Get collection statistics"""
        total_examples = 0
        labeled_examples = 0
        files = list(self.data_dir.glob("decisions.*.jsonl"))

        for log_file in files:
            with open(log_file, 'r') as f:
                for line in f:
                    total_examples += 1
                    example = json.loads(line)
                    if example.get("label") is not None:
                        labeled_examples += 1

        return {
            "total_examples": total_examples,
            "labeled_examples": labeled_examples,
            "unlabeled_examples": total_examples - labeled_examples,
            "labeling_progress": (labeled_examples / total_examples * 100) if total_examples > 0 else 0,
            "log_files": len(files)
        }

    def cleanup_old_logs(self, retention_days=180):
        """Remove logs older than retention period (default: 6 months)"""
        from datetime import timedelta
        import time

        cutoff_time = time.time() - (retention_days * 86400)
        removed_count = 0

        for log_file in self.data_dir.glob("decisions.*.jsonl"):
            if log_file.stat().st_mtime < cutoff_time:
                log_file.unlink()
                removed_count += 1

        if removed_count > 0:
            print(f"[+] Cleaned up {removed_count} old log files")

        return removed_count
