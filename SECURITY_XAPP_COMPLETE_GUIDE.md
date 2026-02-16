# Security Testing xApp - Complete Explanation
## How It Works & How to Use

---

## 📋 Table of Contents
1. [What It Does](#what-it-does)
2. [How It Works](#how-it-works)
3. [Architecture](#architecture)
4. [Installation & Setup](#installation--setup)
5. [Running Tests](#running-tests)
6. [Understanding Results](#understanding-results)
7. [Troubleshooting](#troubleshooting)

---

## 🎯 What It Does

### Purpose
This xApp **tests the security** of your O-RAN Near-RT RIC platform to verify it meets O-RAN security specifications (Chapter 5.1.3 of O-RAN.WG11.TS.SRCS.0-R004-v13.00).

### Think of it as a Security Inspector
Imagine you have a building (Near-RT RIC platform) and you need to verify:
- ✅ All doors have proper locks (Authentication)
- ✅ Only authorized people can enter certain rooms (Authorization)
- ✅ The building can handle a crowd without collapsing (DDoS Protection)
- ✅ Security cameras are recording properly (Logging)
- ✅ The building rejects suspicious visitors (Input Validation)

This xApp is that security inspector - it runs automated tests to check all these things!

### What It Tests

**5 Main Security Categories:**

1. **Authentication (mTLS & Certificates)**
   - Tests: Does the platform require valid certificates?
   - Tests: Is your xApp certificate properly formatted with UUID?
   - Tests: Are weak ciphers rejected?

2. **Authorization (OAuth 2.0)**
   - Tests: Can you get access tokens?
   - Tests: Do tokens actually control access?
   - Tests: Are expired tokens rejected?
   - Tests: Is least privilege enforced?

3. **Data Validation (Injection Protection)**
   - Tests: SQL injection attempts blocked?
   - Tests: Command injection attempts blocked?
   - Tests: Buffer overflow protection working?
   - Tests: Invalid data rejected?

4. **Rate Limiting (DDoS Protection)**
   - Tests: Can platform survive connection floods?
   - Tests: Does it recover from attacks?
   - Tests: Are request bursts handled properly?

5. **Security Logging**
   - Tests: Are security events logged?
   - Tests: Are logs complete and tamper-proof?
   - Tests: Is log retention working?

---

## 🔧 How It Works

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Test xApp                        │
│                                                              │
│  1. Starts → Connects to Near-RT RIC Platform               │
│  2. Authenticates using mTLS certificates                   │
│  3. Gets OAuth 2.0 token                                    │
│  4. Runs 25+ security tests                                 │
│  5. Generates compliance report                             │
│  6. Saves results to JSON file                              │
└─────────────────────────────────────────────────────────────┘
```

### Step-by-Step Process

#### Step 1: Initialization
```python
# When xApp starts (main.py)
xapp = SecurityTestXapp()
xapp.start()
```

**What happens:**
- Loads configuration from `/opt/config/config-file.json`
- Initializes RMR (routing) for messaging
- Sets up test modules (auth, authz, data, rate, logging)
- Prepares metrics collector
- Ready to receive commands

#### Step 2: Test Execution Trigger

**Option A: Automatic (on startup)**
```python
xapp.run_all_tests()  # Runs immediately
```

**Option B: Via RMR Message**
```
Another xApp/platform sends message:
Message Type: 60001 (START_TESTS)
→ xApp receives and starts tests
```

**Option C: Manual (kubectl exec)**
```bash
kubectl exec -it <pod-name> -- python -c "
from src.main import SecurityTestXapp
xapp = SecurityTestXapp()
xapp.run_all_tests()
"
```

#### Step 3: State Machine Orchestration

The xApp uses a **state machine** to organize test execution:

```
IDLE
  ↓
INITIALIZING (load config, check connectivity)
  ↓
AUTHENTICATING (get OAuth token)
  ↓
TESTING_AUTH (run 5 authentication tests)
  ↓
TESTING_AUTHZ (run 6 authorization tests)
  ↓
TESTING_DATA (run 8 data validation tests)
  ↓
TESTING_RATE (run 6 rate limiting tests)
  ↓
TESTING_LOGGING (run 4 logging tests)
  ↓
GENERATING_REPORT (create compliance report)
  ↓
COMPLETED (done!)
```

Each state transition is logged so you can track progress.

#### Step 4: Individual Test Execution

Let's look at one example test: **mTLS Authentication**

```python
# In auth_tests.py
def test_mtls_rest_api(self):
    # 1. Get platform API URL
    api_url = "https://ricplt-appmgr:8080/api"
    
    # 2. Load xApp certificate and key
    cert_file = '/opt/certs/xapp-cert.pem'
    key_file = '/opt/certs/xapp-key.pem'
    ca_file = '/opt/certs/ca-cert.pem'
    
    # 3. Try to connect with mTLS
    response = requests.get(
        f"{api_url}/health",
        cert=(cert_file, key_file),  # Client cert for mTLS
        verify=ca_file,               # Verify server cert
        timeout=5
    )
    
    # 4. Check result
    if response.status_code == 200:
        result = 'PASS'  # mTLS works!
    else:
        result = 'FAIL'  # Something wrong
    
    # 5. Record result
    self.results['mtls_rest_api'] = {
        'status': result,
        'control': 'SEC-CTL-NEAR-RT-1'
    }
```

**What this test does:**
1. Attempts to connect to platform API
2. Uses mTLS (mutual TLS) with certificates
3. Checks if connection succeeds
4. Records whether platform properly requires mTLS

**Why it matters:**
- If this PASSES: Platform correctly enforces mTLS ✅
- If this FAILS: Platform accepts connections without proper auth ❌ (security risk!)

#### Step 5: Report Generation

After all tests complete:

```python
# report_generator.py
def generate(self, test_results):
    report = {
        'metadata': {
            'title': 'Security Compliance Report',
            'generated_at': '2026-02-09T12:00:00',
            'specification': 'O-RAN.WG11.TS.SRCS.0-R004-v13.00'
        },
        'summary': {
            'total_tests': 29,
            'passed': 25,
            'failed': 2,
            'warnings': 2,
            'compliance_rate': 86.2  # Percentage
        },
        'recommendations': [
            {
                'priority': 'HIGH',
                'test': 'sql_injection_protection',
                'issue': 'SQL injection not blocked',
                'recommendation': 'Use parameterized queries'
            }
        ]
    }
    return report
```

Report saved to: `/tmp/security_compliance_report.json`

---

## 🏗️ Architecture

### Component Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                     Security Test xApp                        │
│                                                               │
│  ┌────────────────┐    ┌─────────────────────────────────┐  │
│  │   main.py      │───▶│  SecurityTestXapp (orchestrator) │  │
│  │  (entry point) │    └─────────────┬───────────────────┘  │
│  └────────────────┘                  │                       │
│                                      │                       │
│         ┌────────────────────────────┼──────────────┐       │
│         │                            │              │       │
│         ▼                            ▼              ▼       │
│  ┌─────────────┐          ┌──────────────┐  ┌───────────┐  │
│  │ RMRXapp     │          │ State Machine│  │ Test      │  │
│  │ Framework   │          │ (xDevSM)     │  │ Modules   │  │
│  └──────┬──────┘          └──────┬───────┘  └─────┬─────┘  │
│         │                        │                 │        │
│         │ RMR Messages           │ Orchestrate     │        │
│         │                        │ Execution       │        │
│         │                        │                 │        │
│         ▼                        ▼                 ▼        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Test Execution Layer                     │  │
│  ├──────────┬──────────┬──────────┬──────────┬─────────┤  │
│  │AuthTests │AuthzTests│DataTests │RateTests │LogTests │  │
│  └──────────┴──────────┴──────────┴──────────┴─────────┘  │
│         │                                          │        │
│         └──────────────┬──────────────────────────┘        │
│                        ▼                                    │
│            ┌──────────────────────┐                        │
│            │  Utilities           │                        │
│            ├──────────────────────┤                        │
│            │ • cert_utils.py      │                        │
│            │ • report_generator   │                        │
│            │ • metrics            │                        │
│            └──────────────────────┘                        │
└───────────────────────────────────────────────────────────┘
                        │
                        │ HTTPS/mTLS
                        ▼
        ┌───────────────────────────────┐
        │   Near-RT RIC Platform        │
        │                               │
        │  • Platform APIs              │
        │  • OAuth Server               │
        │  • E2 Termination             │
        │  • Subscription Manager       │
        └───────────────────────────────┘
```

### Key Components Explained

**1. main.py (Entry Point)**
- Starts the xApp
- Handles RMR messages
- Triggers test execution
- Coordinates everything

**2. State Machine (xDevSM)**
- Manages test flow
- Ensures tests run in correct order
- Handles errors gracefully
- Tracks progress

**3. Test Modules (security_tests/)**
- Each module tests one category
- Independent and reusable
- Return structured results
- Can be run individually

**4. Utilities (utils/)**
- **cert_utils**: Validate certificates, extract xApp ID
- **report_generator**: Create JSON/HTML reports
- **metrics**: Track test statistics

**5. RMR Framework**
- Handles message routing
- Communicates with other xApps
- Receives test commands

---

## 📦 Installation & Setup

### Prerequisites

**1. O-RAN Near-RT RIC Platform**
```bash
# Verify platform is running
kubectl get pods -n ricplt
# Should see: appmgr, e2term, submgr, etc.
```

**2. Certificates**
You need 3 certificates:
```
certs/
  ├── xapp-cert.pem   # Your xApp's certificate with UUID
  ├── xapp-key.pem    # Private key for xApp
  └── ca-cert.pem     # Platform CA certificate
```

**Generate xApp certificate with UUID:**
```bash
# Generate UUID
XAPP_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
echo "xApp ID: $XAPP_ID"

# Create certificate with UUID in subjectAltName
# (This would typically be done by your PKI/CA)
```

**3. Tools**
```bash
# Check you have:
kubectl version    # v1.24+
helm version       # v3.10+
docker version     # 20.10+
```

### Step-by-Step Installation

**Step 1: Clone/Download xApp Code**
```bash
# Create project structure
mkdir -p security-test-xapp
cd security-test-xapp

# Copy all files from the documents provided earlier
# Structure should be:
# security-test-xapp/
#   ├── Dockerfile
#   ├── requirements.txt
#   ├── config/
#   ├── src/
#   └── helm/
```

**Step 2: Build Docker Image**
```bash
# Set your registry
export DOCKER_REGISTRY="your-registry.com"

# Build image
docker build -t ${DOCKER_REGISTRY}/security-test-xapp:1.0.0 .

# Push to registry
docker push ${DOCKER_REGISTRY}/security-test-xapp:1.0.0
```

**Step 3: Create Kubernetes Secrets**
```bash
# Create namespace
kubectl create namespace ricxapp

# Create certificate secret
kubectl create secret generic security-xapp-certificates \
  --from-file=xapp-cert.pem=./certs/xapp-cert.pem \
  --from-file=xapp-key.pem=./certs/xapp-key.pem \
  --from-file=ca-cert.pem=./certs/ca-cert.pem \
  -n ricxapp

# Create credentials secret
kubectl create secret generic security-xapp-credentials \
  --from-literal=xapp-id="$(uuidgen | tr '[:upper:]' '[:lower:]')" \
  --from-literal=xapp-secret="$(openssl rand -base64 32)" \
  -n ricxapp
```

**Step 4: Deploy with Helm**
```bash
# Update values.yaml with your registry
vim helm/values.yaml
# Change: repository: your-registry.com/security-test-xapp

# Deploy
helm install security-test-xapp ./helm \
  --namespace ricxapp \
  --create-namespace

# Wait for pod to be ready
kubectl wait --for=condition=ready pod \
  -l app=security-test-xapp \
  -n ricxapp \
  --timeout=300s
```

**Step 5: Verify Deployment**
```bash
# Check pod status
kubectl get pods -n ricxapp

# Should see:
# NAME                                 READY   STATUS    RESTARTS
# security-test-xapp-xxxxxxxxxx-xxxxx  1/1     Running   0

# Check logs
kubectl logs -f -l app=security-test-xapp -n ricxapp

# Should see:
# Security Testing xApp initialized
# Waiting for test trigger...
```

---

## 🚀 Running Tests

### Method 1: Automatic on Startup (Default)

Tests run automatically when xApp starts:

```bash
# Just deploy and watch logs
kubectl logs -f -l app=security-test-xapp -n ricxapp

# Output:
# [1/5] Running Authentication Tests...
#   [1.1] Testing mTLS for REST APIs...
#     ✓ PASS: mTLS authentication working
#   [1.2] Testing xApp Certificate Identity...
#     ✓ PASS: xApp certificate identity valid
# ...
```

### Method 2: Manual Trigger via kubectl exec

```bash
# Get pod name
POD=$(kubectl get pod -n ricxapp -l app=security-test-xapp -o jsonpath='{.items[0].metadata.name}')

# Run tests
kubectl exec -it $POD -n ricxapp -- python -c "
from src.main import SecurityTestXapp
xapp = SecurityTestXapp()
xapp.run_all_tests()
"

# Tests will run and output to console
```

### Method 3: RMR Message Trigger

From another xApp or test client:

```python
# Send RMR message to trigger tests
import rmr

# Initialize RMR
mrc = rmr.rmr_init(b"4560", rmr.RMR_MAX_RCV_BYTES, 0x00)

# Create message
sbuf = rmr.rmr_alloc_msg(mrc, 1024)
rmr.set_payload_and_length(b'{"command": "start_tests"}', sbuf)
sbuf.contents.mtype = 60001  # START_TESTS message type

# Send to security xApp
rmr.rmr_send_msg(mrc, sbuf)
```

### Method 4: Scheduled Tests (Cron)

Run tests periodically:

```yaml
# cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: security-tests-daily
  namespace: ricxapp
spec:
  schedule: "0 2 * * *"  # 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: trigger-tests
            image: your-registry/security-test-xapp:1.0.0
            command:
            - python
            - -c
            - |
              from src.main import SecurityTestXapp
              xapp = SecurityTestXapp()
              xapp.run_all_tests()
          restartPolicy: OnFailure
```

```bash
kubectl apply -f cronjob.yaml
```

---

## 📊 Understanding Results

### Retrieving Test Results

**Option 1: From Pod Logs**
```bash
kubectl logs -l app=security-test-xapp -n ricxapp | tail -100
```

**Option 2: From JSON Report**
```bash
# Copy report from pod
POD=$(kubectl get pod -n ricxapp -l app=security-test-xapp -o jsonpath='{.items[0].metadata.name}')
kubectl cp ricxapp/$POD:/tmp/security_compliance_report.json ./report.json

# View summary
cat report.json | jq .summary
```

**Option 3: Generate HTML Report**
```bash
# In the pod or locally with the JSON
python << EOF
import json
from src.utils.report_generator import SecurityReportGenerator

with open('report.json') as f:
    report = json.load(f)

generator = SecurityReportGenerator()
generator.save_html(report, 'security_report.html')
EOF

# Open in browser
firefox security_report.html
```

### Reading the Report

**Example Report Structure:**

```json
{
  "metadata": {
    "title": "O-RAN Near-RT RIC Security Compliance Report",
    "generated_at": "2026-02-09T14:30:00",
    "specification": "O-RAN.WG11.TS.SRCS.0-R004-v13.00"
  },
  "summary": {
    "total_tests": 29,
    "passed": 25,
    "failed": 2,
    "warnings": 2,
    "errors": 0,
    "skipped": 0,
    "compliance_rate": 86.2,
    "compliant": true
  },
  "compliance_analysis": {
    "authentication": {
      "total": 5,
      "passed": 5,
      "compliance_rate": 100.0,
      "status": "FULLY_COMPLIANT"
    },
    "authorization": {
      "total": 6,
      "passed": 5,
      "compliance_rate": 83.3,
      "status": "COMPLIANT"
    },
    "data_validation": {
      "total": 8,
      "passed": 7,
      "compliance_rate": 87.5,
      "status": "COMPLIANT"
    },
    "rate_limiting": {
      "total": 6,
      "passed": 4,
      "compliance_rate": 66.7,
      "status": "PARTIALLY_COMPLIANT"
    },
    "logging": {
      "total": 4,
      "passed": 4,
      "compliance_rate": 100.0,
      "status": "FULLY_COMPLIANT"
    }
  },
  "recommendations": [
    {
      "priority": "HIGH",
      "category": "data_validation",
      "test": "sql_injection_protection",
      "control": "REQ-SEC-NEAR-RT-7",
      "issue": "SQL injection not blocked",
      "recommendation": "Use parameterized queries, sanitize inputs"
    },
    {
      "priority": "HIGH",
      "category": "rate_limiting",
      "test": "volumetric_ddos_a1",
      "control": "REQ-SEC-NEAR-RT-6",
      "issue": "Platform did not recover from DDoS attack",
      "recommendation": "Implement rate limiting and connection pooling"
    }
  ]
}
```

### What Each Section Means

**1. Summary Section**
```json
"compliance_rate": 86.2,
"compliant": true
```
- **86.2%**: Percentage of tests passed
- **compliant: true**: Platform meets minimum threshold (≥80%)

**Interpretation:**
- ≥ 90%: Excellent security posture ⭐⭐⭐
- 80-89%: Good, but needs improvement ⭐⭐
- 70-79%: Concerning, prioritize fixes ⚠️
- < 70%: Critical issues, urgent action needed ❌

**2. Compliance Analysis (by Category)**
```json
"authentication": {
  "status": "FULLY_COMPLIANT"
}
```

**Status Meanings:**
- **FULLY_COMPLIANT** (100%): Perfect! All tests passed ✅
- **HIGHLY_COMPLIANT** (90-99%): Excellent, minor issues only
- **COMPLIANT** (80-89%): Acceptable, some improvements needed
- **PARTIALLY_COMPLIANT** (70-79%): Significant issues ⚠️
- **NON_COMPLIANT** (< 70%): Critical security gaps ❌

**3. Recommendations Section**

Each recommendation shows:
- **Priority**: HIGH/MEDIUM/LOW (how urgent)
- **Control**: O-RAN security control that failed
- **Issue**: What went wrong
- **Recommendation**: How to fix it

**Example:**
```json
{
  "priority": "HIGH",
  "issue": "SQL injection not blocked",
  "recommendation": "Use parameterized queries, sanitize inputs"
}
```

**Action:** Fix SQL injection vulnerability by implementing parameterized queries.

### Test Result Status Codes

Each individual test has a status:

| Status | Meaning | Action |
|--------|---------|--------|
| **PASS** ✅ | Test passed, control working | No action needed |
| **FAIL** ❌ | Test failed, security gap found | **Fix immediately** |
| **WARN** ⚠️ | Test passed with concerns | Investigate and improve |
| **ERROR** 🔧 | Test couldn't run (technical issue) | Check connectivity/config |
| **SKIP** ⊘ | Test not applicable | Acceptable if documented |

---

## 🔍 Troubleshooting

### Common Issues

**Issue 1: Pod Won't Start**

```bash
# Check pod status
kubectl describe pod -l app=security-test-xapp -n ricxapp

# Common causes:
# 1. Image pull error → Check registry access
# 2. Certificate mount error → Verify secret exists
# 3. Config error → Check ConfigMap
```

**Fix:**
```bash
# Verify secrets exist
kubectl get secrets -n ricxapp | grep security-xapp

# Verify ConfigMap
kubectl get configmap -n ricxapp security-test-xapp-config

# Check events
kubectl get events -n ricxapp --sort-by='.lastTimestamp'
```

**Issue 2: All Tests Fail with Connection Errors**

```
ERROR: Failed to connect to https://ricplt-appmgr:8080/api
```

**Fix:**
```bash
# Test connectivity from pod
kubectl exec -it $POD -n ricxapp -- curl -k https://service-ricplt-appmgr-http.ricplt:8080/api/health

# If fails, check:
# 1. Platform is running
kubectl get pods -n ricplt

# 2. Service exists
kubectl get svc -n ricplt service-ricplt-appmgr-http

# 3. Network policy allows traffic
kubectl get networkpolicy -n ricxapp
```

**Issue 3: Certificate Validation Fails**

```
✗ FAIL: xApp certificate identity validation failed
```

**Fix:**
```bash
# Check certificate format
kubectl exec -it $POD -n ricxapp -- \
  openssl x509 -in /opt/certs/xapp-cert.pem -text -noout | grep -A1 "Subject Alternative Name"

# Should show:
# URI:urn:uuid:XXXXXXXX-XXXX-4XXX-XXXX-XXXXXXXXXXXX

# If missing, regenerate certificate with correct SAN
```

**Issue 4: OAuth Token Errors**

```
✗ FAIL: OAuth 2.0 token acquisition failed
```

**Fix:**
```bash
# Verify OAuth server is reachable
kubectl exec -it $POD -n ricxapp -- \
  curl -k https://service-ricplt-appmgr-http.ricplt:8080/oauth/token

# Check credentials secret
kubectl get secret security-xapp-credentials -n ricxapp -o yaml

# Ensure xapp-id and xapp-secret are set
```

**Issue 5: Tests Timeout**

```
ERROR: Request timeout after 30s
```

**Fix:**
```bash
# Increase timeout in config
kubectl edit configmap security-test-xapp-config -n ricxapp

# Change:
"test_config": {
  "connection_timeout": 60  # Increase from 30 to 60
}

# Restart pod
kubectl delete pod -l app=security-test-xapp -n ricxapp
```

---

## 📈 Best Practices

### 1. Run Tests Regularly

```bash
# Set up daily automated tests
kubectl apply -f cronjob.yaml

# Monitor trends over time
# Compare reports from different dates
```

### 2. Start with Smoke Tests

```bash
# Run quick smoke test first (5-10 min)
# Edit config to enable only critical tests
kubectl exec -it $POD -- python -c "
from src.main import SecurityTestXapp
xapp = SecurityTestXapp()
# Run only auth and authz
xapp.auth_tester.run_tests()
xapp.authz_tester.run_tests()
"
```

### 3. Fix Issues by Priority

From the recommendations:
1. **HIGH priority first** (security vulnerabilities)
2. **MEDIUM priority next** (compliance issues)
3. **LOW priority last** (optimizations)

### 4. Document Exceptions

If a test legitimately fails (by design):
```yaml
# Create exception doc
exceptions:
  - test: "api_discovery_restrictions"
    reason: "Development environment allows full discovery"
    accepted_by: "Security Team"
    date: "2026-02-09"
```

### 5. Integrate with CI/CD

```yaml
# .gitlab-ci.yml or similar
security-compliance-test:
  stage: test
  script:
    - helm install security-test-xapp ./helm
    - kubectl wait --for=condition=ready pod -l app=security-test-xapp
    - kubectl logs -f -l app=security-test-xapp > test-output.log
    - python check_compliance.py test-output.log  # Parse and fail if < 80%
  artifacts:
    paths:
      - security_report.json
```

---

## 🎓 Summary

**This Security xApp:**

✅ **Automates** O-RAN security compliance testing
✅ **Tests** 5 major security categories with 25+ tests
✅ **Generates** detailed JSON/HTML compliance reports
✅ **Identifies** security vulnerabilities and gaps
✅ **Provides** specific remediation recommendations
✅ **Integrates** easily into CI/CD pipelines

**To use it:**
1. Deploy to your Near-RT RIC cluster
2. Run tests (automatically or manually)
3. Review the compliance report
4. Fix HIGH priority issues first
5. Re-run tests to verify fixes
6. Maintain ≥80% compliance rate

**Expected runtime:** 45-60 minutes for full test suite

**Questions?** Check the logs, review test code, or consult the O-RAN specification for control details!
