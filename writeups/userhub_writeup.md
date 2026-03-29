# CTF Writeup: UserHub

**Challenge Name:** UserHub
**Category:** Web / API
**Flag Format:** MythX{...}

### Challenge Description

A user management REST API challenge where you can register, login, and view profile data. The admin panel is protected, but profile update behavior is vulnerable.

---

### Solution

#### Step 1: Registration & Login

- Open the lab in browser and locate the app UI.
- Register a new user with:
  - `username: test`
  - `password: test`
- Login via `/api/login` (e.g., using Postman) to obtain authentication token/session.

#### Step 2: Profile API Exploration

- Call `/api/profile` (GET) to inspect the returned JSON.
- Found fields like `email`, `role`, etc.

#### Step 3: Privilege Escalation via Profile Update

- Send PUT request to `/api/profile` with JSON payload:

```json
{
  "email": "test",
  "role": "admin"
}
```

- The endpoint accepts role updates and applies them directly (insecure authorization checks).

#### Step 4: Access Admin Route

- After profile edit, visit `/admin` page.
- The admin route is now accessible, and the flag appears on the HTML page.

---

### Flag

- Flag was retrieved from `/admin` after promoting role to admin.
- (Insert actual flag text here once obtained.)

---

### Tools Used

- Browser for registration/login flow.
- Postman for API calls (`/api/login`, `/api/profile`).
- HTTP debugger or proxy (optional) to inspect request/responses.
