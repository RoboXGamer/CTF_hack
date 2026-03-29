# CTF Writeup: ProfileHub

**Challenge Name:** ProfileHub
**Category:** Web / Object Injection
**Flag Format:** MythX{...}

### Challenge Description

A web app where profile data can be overridden via a JSON object. The app uses prototype-based authorisation checks, allowing privilege escalation through **proto** pollution.

---

### Solution

#### Step 1: Start Lab and Visit UI

- Open lab URL in browser.
- Find the profile editing / user data endpoint.

#### Step 2: Prototype Override Payload

- Construct an override object to pollute object prototype:

```json
{
  "__proto__": {
    "isAdmin": true
  }
}
```

- Send this payload to the profile/update endpoint.

#### Step 3: Access Admin Panel

- After setting the prototype override, visit admin panel link.
- Permission check now sees `isAdmin=true` on objects, allowing access.
- Flag is revealed on admin page.

---

### Root Cause

- Insecure handling of untrusted JSON via object prototype modification.
- Application logic trusts `isAdmin` property present through prototype chain.

---

### Flag

- Retrieved from admin panel after prototype pollution.
- (Insert exact flag value once confirmed.)

---

### Tools Used

- Browser (lab UI)
- API inspection / proxy (optional)
