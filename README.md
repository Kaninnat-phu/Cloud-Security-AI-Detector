# Cloud-Security-AI-Detector

![Python](https://img.shields.io/badge/Python-3.12-blue)
![AWS](https://img.shields.io/badge/AWS-CloudWatch-orange)
![Docker](https://img.shields.io/badge/Docker-containerized-blue)
![Claude API](https://img.shields.io/badge/Claude-API-purple)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)

An AI-powered cloud security tool that automatically detects suspicious 
activity in AWS CloudWatch logs and generates plain-English incident 
reports using the Claude API — no security analyst required to interpret alerts.

---

## What it does

Most security tools give you raw alerts like `ERROR 403 from 192.168.1.1`.
This tool tells you: *"A user attempted admin access 15 times from an 
unrecognised IP at 3am. This matches a brute-force pattern. Recommend 
immediate investigation."*

- Pulls logs automatically from AWS CloudWatch every 5 minutes
- Scores each log for suspicious behaviour (failed logins, privilege escalation, unusual IPs, off-hours access)
- Sends flagged logs to Claude API for plain-English explanation
- Displays live alerts on a web dashboard
- Runs fully containerized in Docker

---

## Architecture

```
AWS CloudWatch Logs
        │
        ▼
Log Ingestion Script (Python + boto3)
        │
        ▼
Anomaly Detection Engine (Python)
        │
   Suspicious? ──No──▶ Discard
        │
       Yes
        │
        ▼
Claude API (plain-English incident report)
        │
        ▼
Web Dashboard (live alerts)
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Cloud logging | AWS CloudWatch |
| Log ingestion | Python, boto3 |
| Anomaly detection | Python, scikit-learn |
| AI explanation | Claude API (Anthropic) |
| Containerization | Docker |
| Dashboard | Python Flask + HTML |

---

## Security concepts demonstrated

- Log analysis and monitoring (ISC2 CC Domain 5 — Security Operations)
- Anomaly-based intrusion detection
- Cloud security architecture (AWS)
- Incident response automation
- Container security

---

## Project status

- [x] Repository setup
- [x] Step 1: Environment setup (Python, AWS CLI, Docker)
- [x] Step 2: AWS multi-source log pipeline (CloudTrail + VPC Flow Logs + CloudWatch)
- [x] Step 3: Real-time streaming ingestion engine
- [x] Step 4: Behavioral baseline engine
- [ ] Step 5: Attack chain detector
- [ ] Step 6: Claude AI autonomous SOC analyst
- [ ] Step 7: Automated response (SOAR)
- [ ] Step 8: Dashboard + Docker + Kubernetes
---

## About

Built by a 3rd-year Network & Security student at Mahidol University (MUICT)
as a portfolio project targeting a Cloud Security Engineer career path.
