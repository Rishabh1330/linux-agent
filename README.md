# 🛡️ CIS Linux Security Agent – AWS Serverless Reporting System

A lightweight Linux security monitoring system built using **Golang + AWS Serverless Architecture**.

This project collects installed packages and performs 10 CIS Benchmark security checks on Ubuntu 22.04, sends the results securely to AWS, stores them in DynamoDB, and displays structured results in a frontend dashboard.

---

## 📌 Project Overview

This project consists of:

1. ✅ A lightweight Linux Agent written in Go
2. ✅ CIS Benchmark (Level 1) security checks
3. ✅ AWS Serverless backend (API Gateway + Lambda + DynamoDB)
4. ✅ REST APIs to retrieve scan data
5. ✅ A basic frontend dashboard hosted on EC2 (Nginx)

---

## 🏗️ Architecture

Linux Agent (Go)
        ↓
API Gateway (HTTPS)
        ↓
AWS Lambda (Ingestion)
        ↓
DynamoDB (cis-agent-reports)
        ↓
AWS Lambda (Fetch APIs)
        ↓
Frontend Dashboard (Nginx on EC2)

---

## 🚀 Tech Stack

- **Language (Agent):** Golang
- **Backend:** AWS Lambda (Python 3.12)
- **Database:** AWS DynamoDB
- **API Layer:** AWS API Gateway (HTTP API)
- **Frontend:** HTML, CSS, JavaScript
- **Web Server:** Nginx (Ubuntu EC2)
- **Cloud Provider:** AWS

---

## 🔐 Features Implemented

### ✅ 1. Installed Package Collection
- Uses `dpkg -l` (Ubuntu)
- Extracts package name & version
- Sends structured JSON to cloud

---

### ✅ 2. 10 CIS Benchmark Checks (Ubuntu 22.04 - Level 1)

1. Root Login Disabled over SSH  
2. Firewall Enabled (UFW)  
3. Auditd Service Running  
4. AppArmor Enabled  
5. Password Expiration Policy Enforced  
6. Password Complexity Enforced  
7. Unused Filesystems Disabled (cramfs, squashfs)  
8. Time Synchronization (chrony)  
9. No World-Writable Files  
10. GDM Auto-login Disabled  

Each check returns:
- PASS / FAIL
- Evidence
- Summary score (%)

---

### ✅ 3. Secure Cloud Communication

- Agent sends JSON data via HTTPS
- API Gateway endpoint
- Lambda stores report in DynamoDB
- CORS enabled for frontend access

---

### ✅ 4. REST APIs Exposed

| Endpoint | Description |
|----------|-------------|
| `/hosts` | Returns unique hostnames with timestamps |
| `/apps` | Returns installed packages per host |
| `/cis-results` | Returns CIS check results with summary |

Example API Base URL:

```
https://your-api-id.execute-api.region.amazonaws.com/prod
```

---

### ✅ 5. Frontend Dashboard

Hosted using Nginx on EC2.

Displays:
- Host details
- Installed packages
- CIS results (structured view)
- PASS/FAIL highlighting
- Compliance score %

---

## 📂 Project Structure

```
cis-agent/
│
├── agent/
│   ├── main.go
│
├── backend/
│   ├── cis-agent-ingestion.py
│   ├── cis-agent-fetch.py
│
├── frontend/
│   ├── index.html
│
└── README.md
```

---

## 🛠️ Setup Instructions

### 1️⃣ Build Go Agent

```
go mod init cis-agent
go build -o cis-agent
```

### 2️⃣ Install as System Service

```
sudo mv cis-agent /usr/local/bin/
sudo nano /etc/systemd/system/cis-agent.service
sudo systemctl daemon-reload
sudo systemctl enable cis-agent
sudo systemctl start cis-agent
```

---

### 3️⃣ AWS Setup

- Create DynamoDB table: `cis-agent-reports`
- Create Lambda (ingestion)
- Create Lambda (fetch)
- Attach IAM role:
  - AmazonDynamoDBFullAccess
  - AWSLambdaBasicExecutionRole
- Create API Gateway (HTTP API)
- Enable CORS
- Deploy stage (`/prod`)

---

### 4️⃣ Frontend Setup (EC2)

```
sudo apt install nginx
sudo nano /var/www/html/index.html
```

Paste dashboard code and access:

```
http://<your-ec2-public-ip>
```

---

## 📊 Sample JSON Sent by Agent

```json
{
  "hostname": "ip-172-31-39-67",
  "packages": [...],
  "cis_results": [...],
  "summary": {
    "total_checks": 10,
    "passed": 10,
    "failed": 0,
    "score_percent": 100
  }
}
```

---

## 🔥 Key Learning Outcomes

- Golang system programming
- CIS Benchmark security controls
- AWS Serverless architecture
- Lambda & DynamoDB integration
- CORS handling
- API Gateway routing
- Cloud deployment & debugging
- Systemd service configuration

---

## 💰 Cost-Safe Shutdown (After Submission)

To avoid AWS charges:

1. Delete API Gateway
2. Delete Lambda functions
3. Delete DynamoDB table
4. Stop or terminate EC2 instance

---

## 📈 Future Improvements

- Authentication (AWS Cognito)
- Multi-host filtering
- Graphical analytics dashboard
- Report download (PDF)
- Role-based access

---

## 👨‍💻 Author

**Rishabh Verma**  
B.Tech Computer Science  
AWS & Full Stack Developer  

---

## 📌 Project Status

✅ MVP Version Completed  
✅ End-to-End Working  
✅ Agent → Cloud → API → Frontend  

---
