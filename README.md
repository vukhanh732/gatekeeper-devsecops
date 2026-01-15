# 🛡️ Gatekeeper: Automated DevSecOps Pipeline

![Build Status](https://img.shields.io/github/actions/workflow/status/vukhanh732/gatekeeper-devsecops/security-pipeline.yml)
![Security Gate](https://img.shields.io/badge/Security%20Gate-Enforced-green)
![Python](https://img.shields.io/badge/Python-3.9-blue)

## 📖 Project Overview
**Gatekeeper** is an enterprise-grade DevSecOps pipeline designed to enforce "Shift Left" security principles. It automatically detects vulnerabilities in code, dependencies, and runtime environments before they reach production.

Unlike standard CI/CD, this pipeline implements a custom **Python Policy Engine** that aggregates risk data from multiple tools (SAST/SCA) and enforces a strict Quality Gate, blocking builds that violate security standards.

## ⚡ Quick Start (Run this in 5 minutes)
1.  **Fork** this repository.
2.  **Enable Actions:** Go to the "Actions" tab in your forked repo and enable workflows.
3.  **Add Alerts (Optional):**
    *   To get Discord notifications, add a Repository Secret named `DISCORD_WEBHOOK` with your channel's webhook URL.
4.  **Trigger:** Push a change to `README.md` or any file to watch the pipeline run!

## 🏗️ Architecture
The pipeline follows a multi-stage security strategy:

1.  **Static Analysis (SAST):** Scans source code for hardcoded secrets and insecure patterns using **Bandit**.
2.  **Composition Analysis (SCA):** Checks libraries for known CVEs using **Safety**.
3.  **Policy Enforcement:** A custom Python engine blocks the build if High-Severity risks are found.
4.  **Dynamic Analysis (DAST):** Deploys the app to a Docker container and attacks it with **OWASP ZAP** to find runtime flaws (XSS, Injection).
5.  **ChatOps:** Automatically notifies Discord or Microsoft Teams with the scan status.

## 🚀 How It Works
The pipeline is defined in `.github/workflows/security-pipeline.yml`.

### The Security Gate Logic (`security_gate.py`)
I engineered a custom decision engine that parses JSON reports to enforce company policy. The logic ensures that critical risks block the deployment while minor issues only trigger warnings.

## 🛠️ Technology Stack
*   **CI/CD:** GitHub Actions
*   **Containerization:** Docker
*   **SAST:** Bandit
*   **SCA:** Safety
*   **DAST:** OWASP ZAP (Zed Attack Proxy)
*   **Automation:** Python 3.9
*   **Notifications:** Discord Webhooks / Microsoft Teams Cards

## 📊 Results
*   **Before:** Build passed with hardcoded AWS keys and Debug Mode enabled.
*   **After:** Pipeline blocked the build, forced remediation (Environment Variables), and now enforces clean code standards.

## 🏃 How to Run Locally

# Clone the repo
git clone https://github.com/vukhanh732/gatekeeper-devsecops.git

# Run the Environment Setup Script
chmod +x setup_env.sh
./setup_env.sh

# Build and Attack
docker build -t gatekeeper-app .
docker run -p 5000:5000 gatekeeper-app
