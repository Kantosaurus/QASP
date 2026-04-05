import asyncio
from qasp_client import QASPClient

API_KEY = "6f0e275973aa414c9a792cc534e2289a"
BASE_URL = "https://qasp.agis.it.com"

async def main():
    qasp = QASPClient(BASE_URL)
    qasp._api_key = API_KEY
    qasp._did = "did:qasp:7L2cgCEkZuCCX1uog1utP2cQ1YSGYv5vuzBdwNytrFv4"
    
    print("Creating WebSocket listener...")
    
    listener = qasp.create_websocket_listener(
        on_connect=lambda: print("[+] Connected! Aphrodite is online."),
        on_disconnect=lambda: print("[-] Disconnected"),
        on_message=lambda m: print(f"[M] Message: {m}"),
        on_tool_call=lambda c: print(f"[T] Tool call: {c}") or {"result": "ok"},
    )
    
    print("Connecting to WebSocket...")
    await listener.run()

if __name__ == "__main__":
    asyncio.run(main())
