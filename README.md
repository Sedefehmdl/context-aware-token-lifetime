# Context-Aware Token Lifetime Management in Private Cloud Environment

**Course:** Cyber Security Labs I — IPM-22fkbSCLAB1  
**Institution:** Eötvös Loránd University (ELTE), Faculty of Informatics  
**Student:** Sadaf Ahmadli (DJNSX6)  
**Supervisor:** Dr. Mohammed Alshawki  

---

## Overview

OpenStack Keystone issues all authentication tokens with a fixed expiration time of 3600 seconds, regardless of the risk profile of the authenticating session. This project replaces that static policy with a dynamic, context-aware mechanism that computes a session risk score from four contextual signals and maps the score to one of three token lifetime tiers.

The implementation is non-invasive: it targets the `default_expire_time()` function in `keystone/token/provider.py` via a monkey-patch applied at WSGI startup, requiring no modification to Keystone's core source code.

---

## Repository Structure

```
context-aware-token-lifetime/
├── dynamic_lifetime.py      # Monkey-patch module deployed to Keystone WSGI
├── risk_scorer.py           # Standalone risk scoring logic (signals → score → lifetime)
├── known_ips.txt            # Persistent store of previously seen client IP addresses
├── requirements.txt         # Python dependencies
├── tests/
│   └── test_risk_scorer.py  # Unit tests for all three risk scenarios
└── README.md
```

---

## Risk Signal Design

Four contextual signals are evaluated at token issuance time:

| Signal | Source | Trigger Condition | Weight |
|---|---|---|---|
| IP address novelty | WSGI `REMOTE_ADDR` | IP not in `known_ips.txt` | +3 |
| Time of day | `datetime.utcnow().hour` | Outside 06:00–20:00 UTC | +2 |
| Failed login count | Keystone MariaDB | ≥ 3 recent failures | +3 |
| MFA status | Auth request body | MFA method absent | +2 |

The risk score is computed as a weighted sum (maximum: 10) and mapped to a lifetime tier:

| Score Range | Risk Level | Token Lifetime |
|---|---|---|
| 0 – 3 | Low | 7200 s (2 hours) |
| 4 – 6 | Medium | 3600 s (1 hour) |
| 7 – 10 | High | 900 s (15 minutes) |

Signal weights reflect relative severity: IP novelty and repeated login failures are stronger compromise indicators (weight 3), while off-hours access and absent MFA are supplementary signals (weight 2). This design follows Unsel et al. (2023) and Bumiller et al. (2023).

---

## Architecture

```
Keystone WSGI startup
        │
        ▼
keystone-wsgi-public
        │
        ├── import dynamic_lifetime   ← monkey-patch applied here
        │
        ▼
initialize_public_application()
        │
        ▼
POST /v3/auth/tokens
        │
        ▼
default_expire_time()  ← patched function intercepts here
        │
        ├── extract risk signals (IP, time, failures, MFA)
        ├── compute score (0–10)
        ├── map score → lifetime (900 / 3600 / 7200 s)
        ├── write audit log entry
        │
        ▼
Fernet token issued with dynamic expiration
```

---

## Environment

| Component | Details |
|---|---|
| OS | Ubuntu Server 24.04.2 LTS (VirtualBox VM) |
| Identity Service | OpenStack Keystone 25.0.0 |
| Web Server | Apache2 + mod_wsgi |
| Database | MariaDB 10.11 |
| Token Provider | Fernet (dynamic lifetime, patched) |
| Python | 3.12 |

---

## Deployment

### 1. Clone the repository

```bash
git clone https://github.com/Sedefehmdl/context-aware-token-lifetime.git
cd context-aware-token-lifetime
```

### 2. Install dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### 3. Deploy the patch module

```bash
sudo cp dynamic_lifetime.py /usr/lib/python3/dist-packages/
sudo cp known_ips.txt /etc/keystone/known_ips.txt
```

### 4. Apply the WSGI hook

Add the following three lines to `/usr/bin/keystone-wsgi-public`, immediately before the `initialize_public_application()` call:

```python
import sys
sys.path.insert(0, '/usr/lib/python3/dist-packages')
import dynamic_lifetime
```

### 5. Restart Keystone

```bash
sudo systemctl restart apache2
```

### 6. Verify the audit log

```bash
sudo tail -f /var/log/keystone/dynamic_lifetime.log
```

---

## Testing

### Run unit tests

```bash
python3 -m pytest tests/test_risk_scorer.py -v
```

### Live token issuance

```bash
curl -s -X POST http://localhost:5000/v3/auth/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "auth": {
      "identity": {
        "methods": ["password"],
        "password": {
          "user": {
            "name": "admin",
            "domain": {"id": "default"},
            "password": "adminpass123"
          }
        }
      },
      "scope": {
        "project": {
          "name": "admin",
          "domain": {"id": "default"}
        }
      }
    }
  }' | python3 -m json.tool | grep expires_at
```

---

## Test Results (Weeks 5–6)

Three risk scenarios were simulated by temporarily setting signal values and issuing live tokens via the Keystone REST API:

| Scenario | IP Known | Off-Hours | Failed Logins | MFA | Score | Lifetime | Result |
|---|---|---|---|---|---|---|---|
| Low risk | Yes | Yes | 0 | Yes | 2 | 7200 s | ✓ |
| Medium risk | No | Yes | 0 | Yes | 5 | 3600 s | ✓ |
| High risk | No | Yes | 5 | No | 10 | 900 s | ✓ |

Sample audit log output:

```
2026-04-11 20:03:42 TOKEN ISSUED | ip_known=True  | off_hours=True | failed_logins=0 | mfa_used=True  | score=2  | lifetime=7200s
2026-04-11 20:11:06 TOKEN ISSUED | ip_known=False | off_hours=True | failed_logins=5 | mfa_used=False | score=10 | lifetime=900s
2026-04-11 20:16:40 TOKEN ISSUED | ip_known=False | off_hours=True | failed_logins=0 | mfa_used=True  | score=5  | lifetime=3600s
```

---

## Security Properties

| Risk Level | Lifetime | vs. Baseline | Max Exposure Window |
|---|---|---|---|
| Low | 7200 s | +100% | 2 hours |
| Medium | 3600 s | baseline | 1 hour |
| High | 900 s | −75% | 15 minutes |

The high-risk lifetime of 900 seconds reduces the token revocation lag documented by Cui & Xi (2015) by 75%, directly limiting the damage window of a compromised credential.

The patch includes a `try/except` fallback: any unhandled exception in the scoring logic returns the standard 3600-second expiration, ensuring the patch cannot cause a Keystone service outage.

---

## Unique Contribution

A structured audit trail is written to `/var/log/keystone/dynamic_lifetime.log` for every token issued. Each entry records the timestamp, all four signal values, the computed score, and the assigned lifetime. No paper in the reviewed related works implements or proposes such a mechanism alongside dynamic token lifetime management.

---

## Planned Work (Weeks 7–8)

- Replace hardcoded signal values with live extraction:
  - IP from `REMOTE_ADDR` in the WSGI environ, checked against `known_ips.txt`
  - Failed login count from a live MariaDB query on Keystone's credential tables
  - MFA status from the `methods` field of the authentication request
  - Timezone-aware off-hours detection using a configurable UTC offset
- Full scenario testing with live signals across multiple users and sessions
- Performance measurement: latency overhead of the scoring logic vs. static baseline
- Failure-mode testing: explicit exception injection to verify fallback behaviour

---

## References

- Unsel et al. (2023). Risk-based authentication for OpenStack. *ACM CODASPY*.
- Wiefling et al. (2019). Is this really you? *IFIP SEC 2019*.
- Bumiller et al. (2023). On understanding context modelling for adaptive authentication. *ACM TAAS*.
- Cui & Xi (2015). Security analysis of OpenStack Keystone. *IJLTET*.
- Bucko et al. (2023). Enhancing JWT authentication based on user behavior history. *Computers*.
- Wang et al. (2025). Zero-trust based dynamic access control for cloud computing. *Cybersecurity*.# context-aware-token-lifetime
Context-Aware Token Lifetime Management in OpenStack Keystone — ELTE Cyber Security Labs I
