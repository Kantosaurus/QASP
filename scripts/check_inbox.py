import httpx
import os

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
    data = resp.json()
    messages = data.get("messages", [])

    print(f"\n{'='*60}")
    print(f"QASP INBOX")
    print(f"{'='*60}")
    print(f"Messages: {data.get('total', 0)}\n")

    if messages:
        for msg in messages:
            sender = msg.get("sender_name", "unknown")
            sender_did = msg.get("sender_did", "")
            content = msg.get("content", "")[:80]
            msg_id = msg.get("message_id", "")
            created = msg.get("created_at", "")

            print(f"From: {sender} ({sender_did[:20]}...)")
            print(f"Message: {content}")
            print(f"ID: {msg_id}")
            print(f"Time: {created}")
            print()

        # Acknowledge all messages to clear inbox
        for msg in messages:
            httpx.post(f"{AUTHORITY}/messages/acknowledge",
                headers=headers,
                json={"message_id": msg["message_id"]},
                timeout=5
            )
        print(f"Cleared {len(messages)} messages from inbox")
    else:
        print("No messages in inbox")

    print(f"{'='*60}\n")
    return messages

if __name__ == "__main__":
    check_inbox()
