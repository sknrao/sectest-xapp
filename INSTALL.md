# Installation Guide for O-RAN Security Testing xApp

## Prerequisites

1. **O-RAN Near-RT RIC Platform**
   - Version: Latest OSC release
   - Components: Platform Manager, E2 Termination, Subscription Manager

2. **Kubernetes Cluster**
   - Version: 1.24+
   - Namespaces: `ricplt`, `ricxapp`

3. **Tools**
   - kubectl
   - helm (v3.10+)
   - docker
   - git

4. **Certificates**
   - CA certificate for Near-RT RIC
   - xApp certificate with UUID in subjectAltName
   - Private key for xApp

## Step-by-Step Installation

### 1. Clone Repository

\`\`\`bash
git clone https://github.com/your-org/security-test-xapp.git
cd security-test-xapp
\`\`\`

### 2. Configure Certificates

Place your certificates in the `certs/` directory:

\`\`\`bash
mkdir -p certs
# Copy your certificates
cp /path/to/xapp-cert.pem certs/
cp /path/to/xapp-key.pem certs/
cp /path/to/ca-cert.pem certs/
\`\`\`

Verify xApp certificate has UUID:
\`\`\`bash
openssl x509 -in certs/xapp-cert.pem -text -noout | grep -A1 "Subject Alternative Name"
\`\`\`

Should show: \`URI:urn:uuid:XXXXXXXX-XXXX-4XXX-XXXX-XXXXXXXXXXXX\`

### 3. Build Docker Image

\`\`\`bash
export DOCKER_REGISTRY=your-registry.com
chmod +x build.sh
./build.sh
\`\`\`

### 4. Deploy to Near-RT RIC

\`\`\`bash
chmod +x deploy.sh
./deploy.sh
\`\`\`

### 5. Verify Deployment

\`\`\`bash
kubectl get pods -n ricxapp -l app=security-test-xapp
kubectl logs -f -n ricxapp -l app=security-test-xapp
\`\`\`

### 6. Run Security Tests

\`\`\`bash
chmod +x run-tests.sh
./run-tests.sh
\`\`\`

## Test Execution

The xApp will automatically run all security tests:

1. **Authentication Tests** (5-10 minutes)
   - mTLS validation
   - Certificate checks
   - Token management

2. **Authorization Tests** (5 minutes)
   - OAuth 2.0 flows
   - Scope enforcement
   - API access control

3. **Data Validation Tests** (10-15 minutes)
   - Input sanitization
   - Injection protection
   - Schema validation

4. **Rate Limiting Tests** (15-20 minutes)
   - DDoS simulation
   - Recovery testing
   - Burst handling

5. **Logging Tests** (5 minutes)
   - Event generation
   - Log completeness
   - Retention

**Total Duration: 40-55 minutes**

## Viewing Results

Test results are saved in JSON format:

\`\`\`bash
# Results are in the current directory
cat security_report_*.json | jq .

# Or view in pod
kubectl exec -n ricxapp deployment/security-test-xapp -- \
  cat /tmp/security_compliance_report.json
\`\`\`

## Troubleshooting

### Pod not starting
\`\`\`bash
kubectl describe pod -n ricxapp -l app=security-test-xapp
kubectl logs -n ricxapp -l app=security-test-xapp
\`\`\`

### Certificate errors
\`\`\`bash
# Verify cert is valid
openssl verify -CAfile certs/ca-cert.pem certs/xapp-cert.pem

# Check cert dates
openssl x509 -in certs/xapp-cert.pem -noout -dates
\`\`\`

### Connection errors
\`\`\`bash
# Test connectivity from pod
kubectl exec -it -n ricxapp deployment/security-test-xapp -- \
  curl -k https://service-ricplt-appmgr-http.ricplt:8080/api/health
\`\`\`

## Cleanup

\`\`\`bash
chmod +x cleanup.sh
./cleanup.sh
\`\`\`

## Support

For issues, please contact:
- Security Team: security@example.com
- Documentation: https://docs.example.com/security-xapp
\`\`\`

---

## 📊 Expected Test Results

### Pass Criteria

A compliant Near-RT RIC platform should show:

**Authentication:** ✅ 100% pass rate
- mTLS properly configured
- Certificates with valid UUID
- Strong cipher suites only

**Authorization:** ✅ ≥80% pass rate
- OAuth 2.0 working
- Scope enforcement
- API access control

**Data Validation:** ✅ ≥90% pass rate
- Input sanitization
- Injection protection
- Rate limiting on policies

**Rate Limiting:** ✅ ≥70% pass rate
- DDoS protection active
- Platform recovers
- No catastrophic failures

**Logging:** ✅ ≥80% pass rate
- Security events logged
- Logs are complete
- Retention working

### Sample Report Output

\`\`\`json
{
  "metadata": {
    "title": "O-RAN Near-RT RIC Security Compliance Report",
    "specification": "O-RAN.WG11.TS.SRCS.0-R004-v13.00 Chapter 5.1.3",
    "generated_at": "2026-02-09T12:00:00Z",
    "version": "1.0"
  },
  "summary": {
    "total_tests": 25,
    "passed": 22,
    "failed": 1,
    "errors": 0,
    "warnings": 2,
    "skipped": 0,
    "compliance_rate": 88.0
  },
  "detailed_results": {
    "authentication": {
      "mtls_rest_api": {"status": "PASS", "control": "SEC-CTL-NEAR-RT-1"},
      "xapp_cert_identity": {"status": "PASS", "control": "SEC-CTL-NEAR-RT-12,13,14"},
      "invalid_cert_rejection": {"status": "PASS", "control": "SEC-CTL-NEAR-RT-1"},
      "cert_expiry": {"status": "PASS", "control": "SEC-CTL-NEAR-RT-1"},
      "cipher_strength": {"status": "PASS", "control": "SEC-CTL-NEAR-RT-6"}
    }
  },
  "recommendations": [
    {
      "category": "rate_limiting",
      "test": "request_burst",
      "control": "REQ-SEC-NEAR-RT-6",
      "issue": "Moderate burst handling: 65% success",
      "priority": "MEDIUM"
    }
  ]
}
\`\`\`

---

## 🎯 Quick Start (TL;DR)

\`\`\`bash
# 1. Clone and setup
git clone <repo-url> && cd security-test-xapp
mkdir certs && cp /path/to/certs/* certs/

# 2. Build and deploy
./build.sh
./deploy.sh

# 3. Run tests
./run-tests.sh

# 4. View results
cat security_report_*.json | jq .summary
\`\`\`

**That's it!** Your compliance report will be generated automatically.

---

## 📚 Additional Resources

- [O-RAN Security Specifications](https://specifications.o-ran.org/)
- [xApp Developer Guide](https://docs.o-ran-sc.org/)
- [Near-RT RIC Architecture](https://wiki.o-ran-sc.org/)

---

**End of Complete Package**