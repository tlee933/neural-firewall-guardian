# 🧠 Neural Firewall Guardian

**AI-Powered Intrusion Detection System with Machine Learning Threat Classification & Autonomous Response**

Transform your pfSense firewall into an intelligent security perimeter with real-time ML-based threat detection, automated blocking, and comprehensive monitoring.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.7+](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![pfSense](https://img.shields.io/badge/pfSense-2.7+-orange.svg)](https://www.pfsense.org/)

## 🎯 What Is This?

Neural Firewall Guardian is a **next-generation IDS that thinks**. It combines Suricata's proven threat detection with machine learning to:

- 🤖 **Learn normal vs. malicious patterns** using Isolation Forest anomaly detection
- ⚡ **Respond in milliseconds** with automated firewall rule injection
- 📊 **Visualize threats** through Prometheus metrics & Grafana dashboards
- 🛡️ **Protect autonomously** with configurable severity-based actions
- 🔍 **Understand context** by correlating IP behavior, attack patterns, and temporal analysis

**The difference?** Traditional IDS tools alert you. This one **protects you automatically** while you sleep.

## ✨ Key Features

### 🧠 Machine Learning Classification
- **Isolation Forest** for unsupervised anomaly detection
- **Behavioral analysis** tracks per-IP attack patterns
- **Temporal correlation** detects distributed attacks
- **Adaptive scoring** learns from your network's baseline

### ⚡ Automated Response
- **Instant blocking** of critical threats (score ≥ 0.85)
- **Rate limiting** for suspicious activity
- **Auto-expiring rules** prevent permanent lockouts (24h default)
- **Dry-run mode** for testing before production

### 📊 Enterprise Monitoring
- **Prometheus exporter** with 10+ security metrics
- **Grafana dashboard** for real-time threat visualization
- **Alert history** and trend analysis
- **Performance tracking** (sub-millisecond classification)

### 🛡️ Smart Detection
Identifies attack patterns including:
- 🎯 Port scanning (20+ ports in 60s)
- 💥 DoS attacks (10+ alerts/sec)
- 🔍 Network reconnaissance (10+ unique targets)
- 🔑 Brute force attempts (repeated auth failures)
- 🦠 Anomalous traffic (deviation from baseline)

## 🚀 Quick Start

### Prerequisites
```bash
# System requirements
- pfSense 2.7+ with Suricata package installed
- SSH access to pfSense (key-based authentication)
- Python 3.7+ with scikit-learn, numpy
- Prometheus + Grafana (optional, for dashboards)
```

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/neural-firewall-guardian.git
cd neural-firewall-guardian

# 2. Install dependencies
pip3 install -r requirements.txt

# 3. Configure SSH access to pfSense
ssh-copy-id admin@YOUR_PFSENSE_IP

# 4. Test connection
ssh admin@YOUR_PFSENSE_IP "tail -1 /var/log/suricata/eve.json"

# 5. Train ML models on historical data
python3 ai_suricata.py --train --events 5000 --host YOUR_PFSENSE_IP

# 6. Start in dry-run mode (test without blocking)
python3 ai_suricata.py --dry-run --host YOUR_PFSENSE_IP

# 7. Go live with auto-blocking
python3 ai_suricata.py --auto-block --host YOUR_PFSENSE_IP
```

### Systemd Service (Recommended)

```bash
# Install as a system service
sudo cp ai-suricata.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ai-suricata
sudo systemctl start ai-suricata

# Use the management script
./manage.sh watch    # Watch live threats
./manage.sh threats  # Show HIGH/CRITICAL only
./manage.sh stats    # Display statistics
```

## 📖 Documentation

- **[Quick Start Guide](QUICKSTART.md)** - Get running in 5 minutes
- **[Monitoring Setup](MONITORING.md)** - Prometheus & Grafana integration
- **[Configuration Reference](docs/CONFIGURATION.md)** - All options explained
- **[Architecture Deep Dive](docs/ARCHITECTURE.md)** - How it works under the hood

## 🎨 Monitoring Dashboard

Access your threat intelligence dashboard:

```
http://localhost:3000  (Grafana)
- Search for "AI Suricata" dashboard
- View real-time alerts, blocks, and top attackers
- Analyze threat trends and patterns
```

**Dashboard Features:**
- 📈 Alert rate graphs (per second)
- 🥧 Severity distribution (CRITICAL/HIGH/MEDIUM/LOW)
- 🎯 Top attacking IPs with alert counts
- ⚡ Processing performance metrics
- 🛡️ Active blocks and rate limits

**Prometheus Metrics Endpoint:**
```
http://localhost:9102/metrics
```

## 🔧 Configuration

### Environment Variables
```bash
# pfSense Connection
PFSENSE_HOST=192.168.1.1
PFSENSE_USER=admin

# ML Settings
TRAINING_EVENTS=5000
MODEL_PATH=./models/

# Response Settings
AUTO_BLOCK=true
DRY_RUN=false
BLOCK_DURATION_HOURS=24

# Monitoring
PROMETHEUS_PORT=9102
ENABLE_METRICS=true
```

### Threat Scoring Thresholds
```python
SEVERITY_THRESHOLDS = {
    "CRITICAL": 0.85,  # Immediate block
    "HIGH": 0.70,      # Rate limit
    "MEDIUM": 0.50,    # Monitor closely
    "LOW": 0.30,       # Log only
    "INFO": 0.00       # Ignore
}
```

## 🎯 Use Cases

### 1. **Home Lab Security**
Protect your home network from port scanners, brute force attempts, and reconnaissance.

### 2. **Small Business Firewall**
Enterprise-grade threat detection without enterprise costs. Auto-block threats while you focus on business.

### 3. **Honeypot Analysis**
Deploy on a honeypot to study attack patterns and train models on real-world threat data.

### 4. **SOC Monitoring**
Feed alerts into your SIEM, visualize threats in Grafana, track attacker behavior over time.

### 5. **Security Research**
Analyze ML classification accuracy, tune detection models, research new attack patterns.

## 🛠️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Neural Firewall Guardian                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  pfSense Suricata  →  EVE JSON Log  →  ML Classification    │
│  (47,000+ rules)      (SSH stream)      (Isolation Forest)  │
│        │                    │                    │           │
│        ├─ Interface         ├─ Real-time         ├─ Feature  │
│        │  Monitoring        │  Parsing           │  Extract  │
│        │                    │                    │           │
│        └─ Traffic           └─ Alert             └─ Threat   │
│           Analysis              Events               Scoring │
│                                                               │
│                                    ↓                          │
│                         ┌──────────────────────┐             │
│                         │  Automated Response  │             │
│                         ├──────────────────────┤             │
│                         │ • BLOCK (firewall)   │             │
│                         │ • RATE_LIMIT         │             │
│                         │ • MONITOR            │             │
│                         │ • LOG                │             │
│                         └──────────────────────┘             │
│                                    │                          │
│                                    ↓                          │
│                         ┌──────────────────────┐             │
│                         │ Prometheus Metrics   │             │
│                         │ Grafana Dashboard    │             │
│                         └──────────────────────┘             │
└─────────────────────────────────────────────────────────────┘
```

## 📊 Performance

- **Latency:** <100ms per alert classification
- **Throughput:** 1000+ alerts/second
- **Memory:** ~200MB with trained models
- **Storage:** ~1MB per 10,000 alerts (compressed logs)
- **CPU:** ~5% average (idle), ~15% (active training)

## 🧪 Testing

```bash
# Run unit tests
python3 -m pytest tests/

# Test ML classifier
python3 tests/test_classifier.py

# Simulate attack scenarios
python3 tests/simulate_attacks.py

# Benchmark performance
python3 tests/benchmark.py
```

## 🤝 Contributing

Contributions are welcome! Areas needing help:

- 🔬 **New ML models** - Try different algorithms (Random Forest, Neural Nets)
- 🎨 **Dashboard improvements** - More visualizations, better UX
- 📝 **Documentation** - Tutorials, use cases, architecture diagrams
- 🐛 **Bug reports** - Found an issue? Open a ticket!
- ✨ **Feature requests** - Ideas for improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔒 Security Considerations

### False Positives
- **Start with dry-run mode** to tune thresholds for your network
- **Monitor for 24-48 hours** before enabling auto-block
- **Whitelist trusted IPs** in pfSense rules

### Auto-Expiring Blocks
- Blocks expire after 24 hours by default (configurable)
- Prevents permanent lockouts from false positives
- Review blocked IPs regularly

### Logging & Auditing
- All block actions are logged with justification
- Review logs: `~/pfsense/ai_suricata/logs/ai_alerts.jsonl`
- Prometheus metrics track all actions

### Model Security
- Models trained on your network data only
- No external data transmission
- Models stored locally in `./models/`

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built on top of these amazing projects:
- [Suricata IDS](https://suricata.io/) - High-performance network IDS
- [pfSense](https://www.pfsense.org/) - Open-source firewall platform
- [scikit-learn](https://scikit-learn.org/) - Machine learning library
- [Prometheus](https://prometheus.io/) - Monitoring & alerting toolkit
- [Grafana](https://grafana.com/) - Observability dashboards

## 📞 Support

- 🐛 **Bug reports:** [GitHub Issues](https://github.com/yourusername/neural-firewall-guardian/issues)
- 💬 **Discussions:** [GitHub Discussions](https://github.com/yourusername/neural-firewall-guardian/discussions)
- 📧 **Security issues:** security@yourdomain.com (private disclosure)

## 🎯 Roadmap

- [ ] Support for OPNsense firewalls
- [ ] Deep learning threat classifier (LSTM/Transformer)
- [ ] Threat intelligence feed integration
- [ ] Multi-firewall orchestration
- [ ] Mobile app for alerts
- [ ] Slack/Discord/Telegram notifications
- [ ] GeoIP-based threat analysis
- [ ] CVE correlation and exploit detection

---

**Made with 🧠 by security enthusiasts, for security enthusiasts.**

*Star ⭐ this repo if you find it useful!*
