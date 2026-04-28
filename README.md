# 🔐 Real-Time Digital Security Threat Detection Platform

A cloud-native security monitoring platform that ingests live network logs, classifies threats using a trained ML model, and automatically alerts security teams — with human-readable remediation steps.

---

## 📌 Features

- 🔍 Real-time ingestion of network logs and system events via AWS Lambda
- 🧠 ML threat classifier (trained on KDD Cup 99 intrusion dataset)
- 🚨 Automated alerts via SNS with predicted severity (Low / Medium / Critical)
- 📋 Human-readable remediation steps for each threat type
- 📊 CloudWatch dashboard for live threat monitoring
- 🏗️ Full IaC deployment via Terraform
- 🔒 Covers: DoS, Port Scan, Brute Force, Phishing, Data Exfiltration

---

## 🏗️ Architecture

```
Network Logs / System Events
        │
        ▼
  API Gateway (HTTPS)
        │
        ▼
  AWS Lambda (Ingestor)
        │
  ┌─────┴─────┐
  │           │
  ▼           ▼
S3 Archive   ML Classifier Lambda
             │
    ┌────────┴────────┐
    │                 │
    ▼                 ▼
CloudWatch         SNS Topic
(metrics/dashboard) (email + Slack alerts)
                     │
                     ▼
              Security Team
```

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Cloud | AWS Lambda, API Gateway, S3, SNS, CloudWatch, EventBridge |
| ML Model | scikit-learn (Random Forest), trained on KDD Cup 99 |
| IaC | Terraform |
| Language | Python 3.11 |
| Alerting | AWS SNS → Email / Slack webhook |
| Dashboard | CloudWatch + custom HTML report |

---

## 📁 Project Structure

```
security-threat-detection/
├── classifier/
│   ├── train.py            # Train ML model on KDD Cup dataset
│   ├── model.py            # Threat classifier wrapper
│   ├── features.py         # Feature extraction from raw logs
│   └── threat_types.py     # Threat taxonomy + remediation playbook
├── lambda/
│   ├── ingestor/
│   │   └── handler.py      # Receives raw log events
│   └── classifier/
│       └── handler.py      # Runs ML inference + triggers alerts
├── terraform/
│   ├── main.tf             # Core infra
│   ├── lambda.tf           # Lambda functions
│   ├── sns.tf              # Alert topics
│   ├── cloudwatch.tf       # Dashboards + alarms
│   └── variables.tf
├── dashboard/
│   └── index.html          # Local threat dashboard
├── tests/
│   └── test_classifier.py
├── requirements.txt
└── README.md
```

---

## 🚀 Deploy

```bash
# 1. Train the model
pip install -r requirements.txt
python classifier/train.py

# 2. Deploy to AWS
cd terraform
terraform init
terraform plan
terraform apply

# 3. Send a test event
curl -X POST https://<API_GW_URL>/ingest \
  -H "Content-Type: application/json" \
  -d @tests/sample_event.json
```

---

## 🧪 Threat Categories Detected

| Threat | Severity | Example Pattern |
|---|---|---|
| DoS / DDoS | Critical | SYN flood, high connection rate |
| Port Scan | Medium | Sequential port hits from single IP |
| Brute Force | High | Repeated failed auth attempts |
| Phishing | High | Suspicious outbound DNS + payload |
| Data Exfiltration | Critical | Large outbound data burst |
| Normal | — | Baseline traffic |

---

## 📄 License
MIT
