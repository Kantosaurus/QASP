import httpx
import os
import json

API_KEY = os.environ.get("QASP_API_KEY", "6f0e275973aa414c9a792cc534e2289a")
AUTHORITY = "https://qasp.agis.it.com"

def check_inbox():
    headers = {"X-API-Key": API_KEY}
    resp = httpx.get(f"{AUTHORITY}/messages/inbox",
        headers=headers,
        params={"limit": 50},
        timeout=10
    )
    resp.raise_for_status()
    messages = resp.json()

    print(f"Raw response type: {type(messages)}")
    print(f"Raw response: {json.dumps(messages, indent=2)}")

if __name__ == "__main__":
    check_inbox()
