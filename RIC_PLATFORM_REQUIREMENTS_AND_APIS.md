# O-RAN-SC Near-RT RIC Platform Requirements & APIs
## What the Security xApp Expects & Uses

---

## 📋 Table of Contents
1. [Platform Expectations Overview](#platform-expectations-overview)
2. [Required Platform Components](#required-platform-components)
3. [Platform APIs Used](#platform-apis-used)
4. [Authentication & Authorization Setup](#authentication--authorization-setup)
5. [Network & Connectivity](#network--connectivity)
6. [Platform Configuration](#platform-configuration)
7. [API Endpoint Details](#api-endpoint-details)
8. [Expected Behaviors](#expected-behaviors)

---

## 🎯 Platform Expectations Overview

### What We Assume About Your O-RAN-SC RIC Platform

The security xApp is designed specifically for **O-RAN-SC (O-RAN Software Community)** Near-RT RIC implementation. Here's what it expects:

```
┌─────────────────────────────────────────────────────────────┐
│              O-RAN-SC Near-RT RIC Platform                   │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   AppMgr     │  │  E2 Manager  │  │   Submgr     │     │
│  │ (Platform    │  │ (E2 Term)    │  │ (Subscription│     │
│  │  Manager)    │  │              │  │  Manager)    │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                  │                  │             │
│         │     ┌────────────┴────────┐        │             │
│         │     │   RMR (Routing)     │        │             │
│         │     └─────────────────────┘        │             │
│         │                                     │             │
│  ┌──────┴──────────────────────────────────┴───────┐      │
│  │         Platform REST APIs (HTTPS)              │      │
│  │  • xApp Management API                          │      │
│  │  • OAuth 2.0 Token Endpoint                     │      │
│  │  • E2 Subscription API                          │      │
│  │  • A1 Policy API                                │      │
│  │  • Security Log API                             │      │
│  └─────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Required Platform Components

### 1. Application Manager (AppMgr)

**What it is:** Core component managing xApp lifecycle

**What we expect:**
- Running at: `service-ricplt-appmgr-http.ricplt:8080`
- Provides REST API over HTTPS
- Supports mTLS for client authentication
- Has OAuth 2.0 authorization server built-in or integrated

**Used for:**
- xApp registration and lifecycle
- Health checks
- Platform API access
- OAuth token generation

**Verification:**
```bash
# Check if AppMgr is running
kubectl get pods -n ricplt -l app=ricplt-appmgr

# Expected output:
# NAME                                READY   STATUS    RESTARTS
# ricplt-appmgr-xxxxxxxxxx-xxxxx      1/1     Running   0

# Test connectivity
kubectl exec -it <test-pod> -- curl -k https://service-ricplt-appmgr-http.ricplt:8080/api/health
```

### 2. E2 Manager (E2 Termination)

**What it is:** Manages E2 interface connections with RAN nodes

**What we expect:**
- Running and accessible
- Exposes E2 subscription API
- Validates E2 subscription requests
- Enforces rate limiting on E2 operations

**Used for:**
- Testing E2 subscription data validation (SEC-CTL-NEAR-RT-17, 18)
- Testing E2 interface security controls

**Verification:**
```bash
kubectl get pods -n ricplt -l app=ricplt-e2mgr

# Test E2 subscription API
curl -X GET https://service-ricplt-appmgr-http.ricplt:8080/api/subscriptions \
  -H "Authorization: Bearer $TOKEN" \
  --cert xapp-cert.pem --key xapp-key.pem
```

### 3. Subscription Manager (SubmMgr)

**What it is:** Manages E2 subscriptions from xApps

**What we expect:**
- Validates subscription requests
- Enforces authorization policies
- Maintains subscription state

**Used for:**
- Testing subscription API security
- Validating authorization for E2 subscriptions

### 4. RMR (RIC Message Router)

**What it is:** Message routing infrastructure for xApp communication

**What we expect:**
- Running at: `service-ricplt-rtmgr-rmr.ricplt:4561`
- Provides routing table updates
- Routes messages between xApps

**Configuration needed:**
```bash
# RMR environment variables in xApp
RMR_SEED_RT=/opt/route/local.rt
RMR_RTG_SVC=service-ricplt-rtmgr-rmr.ricplt:4561
```

### 5. Security Infrastructure

**What we expect:**

**a) Certificate Authority (CA)**
- Issues certificates for xApps
- xApp certificates have UUID v4 in subjectAltName
- Format: `URI:urn:uuid:XXXXXXXX-XXXX-4XXX-XXXX-XXXXXXXXXXXX`

**b) OAuth 2.0 Server**
- Integrated with AppMgr or standalone
- Supports client_credentials grant
- Issues JWT access tokens
- Token endpoint: `/oauth/token`

**c) TLS/mTLS**
- All APIs require HTTPS
- Client certificate authentication (mTLS) enforced
- Strong cipher suites only (TLS 1.2+)
- Certificate validation enabled

---

## 🌐 Platform APIs Used

### Complete API Inventory

Here are **ALL** the APIs the security xApp interacts with:

### API Category 1: Platform Management APIs

#### 1.1 Health Check API
```
GET /api/health
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: None (public endpoint)
```

**Purpose:** Verify platform is operational

**Expected Response:**
```json
HTTP/1.1 200 OK
{
  "status": "healthy",
  "timestamp": "2026-02-09T12:00:00Z"
}
```

**Used in tests:**
- Authentication tests (mTLS validation)
- Rate limiting tests (health endpoint bombardment)

---

#### 1.2 xApp Discovery API
```
GET /api/services
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token (OAuth 2.0)
```

**Purpose:** Discover available platform services

**Expected Response:**
```json
HTTP/1.1 200 OK
[
  {
    "name": "e2term",
    "description": "E2 Termination service",
    "version": "1.0",
    "endpoints": ["/api/e2/subscriptions"]
  },
  {
    "name": "submgr",
    "description": "Subscription Manager",
    "version": "1.0",
    "endpoints": ["/api/subscriptions"]
  }
]
```

**Used in tests:**
- Authorization tests (API discovery restrictions - SEC-CTL-NEAR-RT-3C)
- Verify only authorized APIs are visible

---

### API Category 2: OAuth 2.0 / Authorization APIs

#### 2.1 OAuth Token Endpoint
```
POST /oauth/token
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Content-Type: application/x-www-form-urlencoded
```

**Request:**
```
grant_type=client_credentials
client_id=<xapp-uuid>
client_secret=<xapp-secret>
scope=platform:read platform:write
```

**Expected Response:**
```json
HTTP/1.1 200 OK
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "platform:read platform:write"
}
```

**Used in tests:**
- Authorization tests (OAuth 2.0 token flow - SEC-CTL-NEAR-RT-3)
- Token validation
- Scope enforcement

---

#### 2.2 Token Introspection (Optional)
```
POST /oauth/introspect
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
```

**Request:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Expected Response:**
```json
HTTP/1.1 200 OK
{
  "active": true,
  "scope": "platform:read platform:write",
  "client_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "exp": 1707484800
}
```

---

### API Category 3: E2 Subscription APIs

#### 3.1 Create E2 Subscription
```
POST /api/subscriptions
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token
Content-Type: application/json
```

**Request:**
```json
{
  "ClientEndpoint": {
    "Host": "security-test-xapp.ricxapp",
    "HTTPPort": 8080,
    "RMRPort": 4560
  },
  "Meid": "gnb_001",
  "RANFunctionID": 1,
  "SubscriptionDetails": [
    {
      "XappEventInstanceId": 12345,
      "EventTriggers": [1, 2, 3],
      "ActionToBeSetup": [
        {
          "ActionID": 1,
          "ActionType": "report",
          "ActionDefinition": "base64encodeddata",
          "SubsequentAction": {
            "SubsequentActionType": "continue",
            "TimeToWait": "w10ms"
          }
        }
      ]
    }
  ]
}
```

**Expected Response (Success):**
```json
HTTP/1.1 201 Created
{
  "SubscriptionId": "sub-12345-67890",
  "SubscriptionInstances": [
    {
      "XappEventInstanceId": 12345,
      "E2EventInstanceId": 1
    }
  ]
}
```

**Expected Response (Validation Failure):**
```json
HTTP/1.1 400 Bad Request
{
  "error": "validation_failed",
  "message": "Invalid RANFunctionID: must be positive integer",
  "field": "RANFunctionID"
}
```

**Used in tests:**
- Data validation tests (E2 subscription validation - SEC-CTL-NEAR-RT-17, 18)
- Authorization tests (verify subscription authorization)
- Input sanitization (reject malicious inputs)

---

#### 3.2 List E2 Subscriptions
```
GET /api/subscriptions
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token
```

**Expected Response:**
```json
HTTP/1.1 200 OK
[
  {
    "SubscriptionId": "sub-12345-67890",
    "Meid": "gnb_001",
    "ClientEndpoint": "security-test-xapp.ricxapp:4560"
  }
]
```

---

#### 3.3 Delete E2 Subscription
```
DELETE /api/subscriptions/{subscriptionId}
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token
```

**Expected Response:**
```json
HTTP/1.1 204 No Content
```

---

### API Category 4: A1 Policy APIs

#### 4.1 Create A1 Policy
```
PUT /a1-p/policytypes/{policyTypeId}/policies/{policyId}
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token
Content-Type: application/json
```

**Request:**
```json
{
  "policy_type_id": "20008",
  "ric_id": "ric1",
  "policy_data": {
    "threshold": 10,
    "scope": {
      "ue_id": "imsi-123456789012345",
      "cell_id": 12345
    }
  }
}
```

**Expected Response (Success):**
```json
HTTP/1.1 201 Created
{
  "policy_id": "test-policy-001",
  "status": "created"
}
```

**Expected Response (Validation Failure):**
```json
HTTP/1.1 400 Bad Request
{
  "error": "schema_validation_failed",
  "message": "Policy does not conform to schema",
  "details": "threshold must be between 1 and 100"
}
```

**Used in tests:**
- Data validation tests (A1 policy validation - SEC-CTL-NEAR-RT-8)
- Schema validation
- Value range validation
- Rate limiting validation

---

#### 4.2 Get A1 Policy Types
```
GET /a1-p/policytypes
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token
```

**Expected Response:**
```json
HTTP/1.1 200 OK
[20008, 20009, 20010]
```

---

#### 4.3 Get A1 Policies
```
GET /a1-p/policytypes/{policyTypeId}/policies
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token
```

**Expected Response:**
```json
HTTP/1.1 200 OK
["policy-001", "policy-002", "policy-003"]
```

---

### API Category 5: Security Logging APIs

#### 5.1 Query Security Logs
```
GET /api/logs/security
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token
Query Parameters:
  - timeframe: 1m, 5m, 1h, 24h, 7d
  - severity: info, warning, error, critical
  - event_type: auth_failure, validation_failure, rate_limit
  - limit: max results to return
```

**Expected Response:**
```json
HTTP/1.1 200 OK
[
  {
    "id": "log-12345",
    "timestamp": "2026-02-09T12:00:00Z",
    "severity": "warning",
    "event_type": "validation_failure",
    "source": "appmgr",
    "message": "Invalid policy schema rejected",
    "details": {
      "client_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
      "endpoint": "/a1-p/policies",
      "reason": "schema_mismatch"
    }
  },
  {
    "id": "log-12346",
    "timestamp": "2026-02-09T12:00:05Z",
    "severity": "error",
    "event_type": "auth_failure",
    "source": "appmgr",
    "message": "Client certificate validation failed",
    "details": {
      "ip_address": "10.244.1.5",
      "reason": "certificate_expired"
    }
  }
]
```

**Used in tests:**
- Logging tests (security event logging - SEC-CTL-NEAR-RT-8, 16, 17, 18)
- Verify validation failures are logged
- Check log completeness

---

#### 5.2 Security Log Access Control (Should Fail)
```
PUT /api/logs/security/{logId}
DELETE /api/logs/security/{logId}
```

**Expected Response:**
```json
HTTP/1.1 403 Forbidden
{
  "error": "operation_not_permitted",
  "message": "Security logs are immutable"
}
```

**Used in tests:**
- Logging tests (log integrity - verify logs cannot be modified)

---

### API Category 6: Administrative APIs (Limited Access)

#### 6.1 Admin Configuration API
```
GET /api/admin/config
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token (requires admin scope)
```

**Expected Response (Without Admin Scope):**
```json
HTTP/1.1 403 Forbidden
{
  "error": "insufficient_scope",
  "message": "Admin scope required"
}
```

**Used in tests:**
- Authorization tests (scope enforcement - SEC-CTL-NEAR-RT-3B)
- Verify least privilege principle

---

#### 6.2 Admin Secrets API
```
GET /api/admin/secrets
Host: service-ricplt-appmgr-http.ricplt:8080
Protocol: HTTPS
Authentication: mTLS
Authorization: Bearer token (requires admin scope)
```

**Expected Response (Without Admin Scope):**
```json
HTTP/1.1 403 Forbidden
{
  "error": "insufficient_scope",
  "message": "Admin scope required"
}
```

---

## 🔐 Authentication & Authorization Setup

### What the Platform MUST Support

#### 1. Mutual TLS (mTLS)

**Certificate Requirements:**

**For xApp Certificate:**
```
Subject: CN=security-test-xapp
Issuer: CN=O-RAN Platform CA
Valid: 2026-01-01 to 2027-01-01
Subject Alternative Name:
  URI:urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6  ← UUID v4 format
```

**Platform Configuration:**
```yaml
# In platform config (AppMgr)
tls:
  enabled: true
  mtls_required: true  # Must be true
  client_auth: required
  ca_certificate: /path/to/ca-cert.pem
  server_certificate: /path/to/server-cert.pem
  server_key: /path/to/server-key.pem
  min_tls_version: "1.2"
  cipher_suites:
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  # Weak ciphers must be disabled
```

**What we test:**
- Platform requires client certificate
- Platform validates certificate against CA
- Platform rejects invalid/expired certificates
- Platform uses strong cipher suites only

---

#### 2. OAuth 2.0

**Required Grant Types:**
- `client_credentials` (for xApp-to-Platform auth)

**Token Format:**
```
JWT (JSON Web Token)
Algorithm: RS256 (RSA with SHA-256)
```

**Token Claims:**
```json
{
  "iss": "https://ricplt-appmgr.ricplt",
  "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "aud": "ric-platform",
  "exp": 1707484800,
  "iat": 1707481200,
  "scope": "platform:read platform:write",
  "client_id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
}
```

**Platform Configuration:**
```yaml
oauth:
  enabled: true
  token_endpoint: /oauth/token
  introspection_endpoint: /oauth/introspect
  token_ttl: 3600  # 1 hour
  refresh_token_enabled: false  # Not needed for client_credentials
  scopes:
    - platform:read
    - platform:write
    - admin:read
    - admin:write
  validation:
    verify_signature: true
    verify_expiration: true
    verify_audience: true
```

---

## 🌐 Network & Connectivity

### Namespace Layout

```
┌─────────────────────────────────────────────────┐
│  Kubernetes Cluster                              │
│                                                  │
│  ┌────────────────────────────────────────┐    │
│  │  ricplt namespace (Platform)           │    │
│  │                                         │    │
│  │  • service-ricplt-appmgr-http:8080     │    │
│  │  • service-ricplt-e2mgr-http:3800      │    │
│  │  • service-ricplt-rtmgr-rmr:4561       │    │
│  └──────────────┬──────────────────────────┘    │
│                 │                                │
│                 │ (Network Policy allows)        │
│                 │                                │
│  ┌──────────────▼──────────────────────────┐    │
│  │  ricxapp namespace (xApps)              │    │
│  │                                         │    │
│  │  • security-test-xapp:4560 (RMR)       │    │
│  │  • security-test-xapp:8080 (HTTP)      │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

### Required Network Policies

**Allow xApp → Platform communication:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-xapp-to-platform
  namespace: ricplt
spec:
  podSelector:
    matchLabels:
      app: ricplt-appmgr
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ricxapp
    ports:
    - protocol: TCP
      port: 8080  # HTTPS API
```

### DNS Resolution

**Required service names resolvable from ricxapp namespace:**
```
service-ricplt-appmgr-http.ricplt.svc.cluster.local
service-ricplt-e2mgr-http.ricplt.svc.cluster.local
service-ricplt-rtmgr-rmr.ricplt.svc.cluster.local
```

**Test:**
```bash
kubectl exec -it <xapp-pod> -n ricxapp -- \
  nslookup service-ricplt-appmgr-http.ricplt
```

---

## ⚙️ Platform Configuration

### AppMgr Configuration

**Expected configuration file (appconfig.yaml):**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ricplt-appmgr-config
  namespace: ricplt
data:
  appmgr.yaml: |
    server:
      host: 0.0.0.0
      port: 8080
      tls:
        enabled: true
        cert: /opt/certs/server-cert.pem
        key: /opt/certs/server-key.pem
        ca: /opt/certs/ca-cert.pem
        client_auth: required
    
    oauth:
      enabled: true
      provider: internal  # or keycloak, etc.
      token_ttl: 3600
    
    api:
      rate_limit:
        enabled: true
        requests_per_second: 100
        burst: 200
      
      validation:
        enabled: true
        schema_enforcement: true
        
      logging:
        security_events: true
        audit_log: /var/log/appmgr/security-audit.log
    
    xapp:
      certificate_validation:
        enabled: true
        require_uuid: true  # Verify xApp ID in cert
        uuid_location: subjectAltName
```

### E2 Manager Configuration

```yaml
e2manager:
  subscription:
    validation:
      enabled: true
      max_rate: 10  # subscriptions per second per xApp
    
    authorization:
      enabled: true
      policy_enforcement: true
```

---

## 📊 Expected Behaviors

### What Should Happen (PASS Scenarios)

#### 1. Authentication

**Scenario:** xApp connects with valid mTLS certificate
```
xApp → [TLS Handshake with client cert] → Platform
Platform ← [200 OK] ← validates cert, extracts UUID
```
**Result:** ✅ PASS

**Scenario:** xApp connects without client certificate
```
xApp → [TLS Handshake without client cert] → Platform
Platform ← [401 Unauthorized or TLS Error] ← rejects connection
```
**Result:** ✅ PASS (platform correctly rejects)

---

#### 2. Authorization

**Scenario:** xApp requests token with valid credentials
```
POST /oauth/token
  grant_type=client_credentials
  client_id=<uuid>
  client_secret=<secret>

Platform validates credentials
Platform generates JWT token
Platform ← [200 OK + access_token]
```
**Result:** ✅ PASS

**Scenario:** xApp tries to access API without token
```
GET /api/subscriptions
Authorization: (none)

Platform checks for token
Platform ← [401 Unauthorized]
```
**Result:** ✅ PASS (platform correctly enforces auth)

**Scenario:** xApp tries to access admin API with non-admin token
```
GET /api/admin/config
Authorization: Bearer <token with scope=platform:read>

Platform checks token scope
Platform ← [403 Forbidden - insufficient_scope]
```
**Result:** ✅ PASS (least privilege enforced)

---

#### 3. Data Validation

**Scenario:** xApp sends invalid A1 policy
```
PUT /a1-p/policies
{
  "threshold": -1,  # Invalid: negative value
  "cell_id": "'; DROP TABLE--"  # SQL injection attempt
}

Platform validates schema
Platform validates values
Platform sanitizes input
Platform ← [400 Bad Request - validation_failed]
Platform logs security event
```
**Result:** ✅ PASS (malicious input rejected and logged)

---

#### 4. Rate Limiting

**Scenario:** xApp sends 1000 requests in 1 second
```
xApp sends burst of 1000 requests

Platform tracks request rate
After 100 requests: Platform ← [429 Too Many Requests]
Platform continues operating normally
```
**Result:** ✅ PASS (platform survives and rate limits)

---

#### 5. Security Logging

**Scenario:** xApp triggers validation failure
```
xApp sends invalid request
Platform rejects request with 400
Platform writes log entry:
{
  "timestamp": "2026-02-09T12:00:00Z",
  "event_type": "validation_failure",
  "source": "appmgr",
  "client_id": "<xapp-uuid>",
  "message": "Invalid policy schema"
}

Later: xApp queries logs
Platform ← [200 OK + log entries]
```
**Result:** ✅ PASS (event logged and retrievable)

---

### What Should NOT Happen (FAIL Scenarios)

#### ❌ Platform accepts connections without client certificates
**Impact:** Anyone can connect (authentication bypass)

#### ❌ Platform accepts expired/invalid tokens
**Impact:** Unauthorized access possible

#### ❌ Platform doesn't validate input data
**Impact:** SQL injection, command injection possible

#### ❌ Platform crashes under high load
**Impact:** DoS vulnerability

#### ❌ Platform allows log modification
**Impact:** Attacker can cover tracks

---

## 📝 Summary: Platform Checklist

### ✅ Must Have

- [ ] **AppMgr running** with HTTPS enabled
- [ ] **mTLS enforced** on all API endpoints
- [ ] **OAuth 2.0 server** integrated (token endpoint)
- [ ] **xApp certificates** have UUID in subjectAltName
- [ ] **Strong ciphers only** (TLS 1.2+, no weak ciphers)
- [ ] **Input validation** on all APIs (schema + values)
- [ ] **Rate limiting** configured (prevent DDoS)
- [ ] **Authorization enforcement** (token validation, scopes)
- [ ] **Security logging** enabled (audit trail)
- [ ] **Network policies** allow ricxapp → ricplt

### 🔍 API Endpoints Required

| API | Endpoint | Purpose |
|-----|----------|---------|
| Health Check | `GET /api/health` | Platform status |
| OAuth Token | `POST /oauth/token` | Get access token |
| Service Discovery | `GET /api/services` | List available services |
| E2 Subscriptions | `POST /api/subscriptions` | Create subscription |
| E2 Subscriptions | `GET /api/subscriptions` | List subscriptions |
| A1 Policies | `PUT /a1-p/policies` | Create policy |
| A1 Policy Types | `GET /a1-p/policytypes` | List policy types |
| Security Logs | `GET /api/logs/security` | Query logs |
| Admin (Protected) | `GET /api/admin/*` | Admin endpoints (should reject non-admin) |

### 📋 Configuration Values

```yaml
# Minimum platform configuration
platform:
  tls:
    mtls_required: true
    min_version: "1.2"
  
  oauth:
    enabled: true
    token_ttl: 3600
  
  rate_limiting:
    enabled: true
    max_requests_per_second: 100
  
  validation:
    schema_validation: true
    input_sanitization: true
  
  logging:
    security_events: true
    log_retention_days: 90
```

---

## 🎯 Quick Verification Commands

```bash
# 1. Check platform components
kubectl get pods -n ricplt

# 2. Test AppMgr connectivity
kubectl exec -it <xapp-pod> -n ricxapp -- \
  curl -k https://service-ricplt-appmgr-http.ricplt:8080/api/health

# 3. Test mTLS enforcement
kubectl exec -it <xapp-pod> -n ricxapp -- \
  curl -k https://service-ricplt-appmgr-http.ricplt:8080/api/health
# Should fail without client cert!

# 4. Test OAuth token endpoint
kubectl exec -it <xapp-pod> -n ricxapp -- \
  curl -k -X POST https://service-ricplt-appmgr-http.ricplt:8080/oauth/token \
  -d "grant_type=client_credentials&client_id=test&client_secret=test"

# 5. Check security logs
kubectl logs -n ricplt -l app=ricplt-appmgr | grep security
```

---

This is **exactly** what your O-RAN-SC platform needs to support for the security xApp to work! 🚀
