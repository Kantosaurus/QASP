import asyncio
import os
from qasp_client import QASPClient

API_KEY = os.environ.get("QASP_API_KEY", "6f0e275973aa414c9a792cc534e2289a")
DID = os.environ.get("QASP_DID", "did:qasp:7L2cgCEkZuCCX1uog1utP2cQ1YSGYv5vuzBdwNytrFv4")
BASE_URL = "https://qasp.agis.it.com"
AGENT_NAME = "Aphrodite"

def on_message(payload: dict) -> None:
    """Surface incoming messages to the user - never consume silently."""
    sender = payload.get("sender_name", payload.get("initiator_name", "unknown"))
    sender_did = payload.get("sender_did", payload.get("initiator_did", "unknown"))
    content = payload.get("content", "")
    msg_id = payload.get("message_id", "")
    intent = payload.get("intent", "")
    conv_id = payload.get("conversation_id", "")

    print(f"\n{'='*60}")
    print(f"[QASP] MESSAGE RECEIVED")
    print(f"{'='*60}")
    print(f"From: {sender} ({sender_did[:20]}...)")
    print(f"Conversation: {conv_id[:16]}..." if conv_id else "Conversation: N/A")
    if intent:
        print(f"Intent: {intent}")
    print(f"{'-'*60}")
    print(content)
    print(f"{'='*60}\n")

def on_conversation(payload: dict) -> None:
    """Handle new conversation invitations."""
    initiator = payload.get("initiator_name", "unknown")
    initiator_did = payload.get("initiator_did", "unknown")
    topic = payload.get("topic", "")
    conv_id = payload.get("conversation_id", "")

    print(f"\n{'='*60}")
    print(f"[QASP] CONVERSATION OPENED")
    print(f"{'='*60}")
    print(f"From: {initiator} ({initiator_did[:20]}...)")
    print(f"Conversation ID: {conv_id}")
    if topic:
        print(f"Topic: {topic}")
    print(f"{'='*60}\n")

def on_tool_call(payload: dict) -> dict:
    """Handle tool calls from other agents."""
    caller = payload.get("caller_did", "unknown")
    tool_name = payload.get("tool_name", "")
    args = payload.get("arguments", {})

    print(f"\n{'='*60}")
    print(f"[QASP] TOOL CALL RECEIVED")
    print(f"{'='*60}")
    print(f"From: {caller[:20]}...")
    print(f"Tool: {tool_name}")
    print(f"Arguments: {args}")
    print(f"{'='*60}\n")

    # Simple echo tool for now
    if tool_name == "echo":
        result = {"echo": args.get("msg", ""), "agent": AGENT_NAME}
    else:
        result = {"error": f"Tool '{tool_name}' not implemented"}

    return result

def on_connect() -> None:
    print(f"[QASP] {AGENT_NAME} is ONLINE")

def on_disconnect() -> None:
    print(f"[QASP] {AGENT_NAME} is OFFLINE")

async def main():
    qasp = QASPClient(BASE_URL)
    qasp._api_key = API_KEY
    qasp._did = DID
    qasp._agent_name = AGENT_NAME

    print(f"Starting {AGENT_NAME}...")
    print(f"DID: {DID}")

    listener = qasp.create_websocket_listener(
        on_message=on_message,
        on_conversation=on_conversation,
        on_tool_call=on_tool_call,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
    )

    print("Connecting to QASP WebSocket...")
    await listener.run()

if __name__ == "__main__":
    asyncio.run(main())
