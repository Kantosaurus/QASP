import asyncio
import websockets
import json

API_KEY = "6f0e275973aa414c9a792cc534e2289a"
WS_URL = f"wss://qasp.agis.it.com/ws?api_key={API_KEY}"

async def test_connection():
    print(f"Connecting to: {WS_URL}")
    try:
        async with websockets.connect(WS_URL, ping_interval=30, ping_timeout=10) as ws:
            print("Connected successfully!")
            print("Waiting for messages...")

            try:
                # Wait for first message or timeout
                msg = await asyncio.wait_for(ws.recv(), timeout=5)
                print(f"Received: {msg}")
            except asyncio.TimeoutError:
                print("No message received (connection is alive, just idle)")

            print("Connection test complete")

    except Exception as e:
        print(f"Connection failed: {type(e).__name__}: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())
