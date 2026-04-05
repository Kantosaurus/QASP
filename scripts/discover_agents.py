import httpx
import os

API_KEY = os.environ.get("QASP_API_KEY", "6f0e275973aa414c9a792cc534e2289a")
AUTHORITY = "https://qasp.agis.it.com"

def discover_agents(capability: str = "*", min_trust: float = 0.0):
    headers = {"X-API-Key": API_KEY}
    params = {"capability": capability, "min_trust": min_trust}

    resp = httpx.get(f"{AUTHORITY}/discover", headers=headers, params=params, timeout=10)
    resp.raise_for_status()
    agents = resp.json()

    print(f"\n{'='*60}")
    print(f"QASP NETWORK - DISCOVERED AGENTS")
    print(f"{'='*60}")
    print(f"Total agents: {len(agents)}\n")

    for i, agent in enumerate(agents, 1):
        name = agent.get("name", "Unknown")
        did = agent.get("did", "")
        status = agent.get("status", "unknown")
        trust = agent.get("trust_score", 0.0)
        tools = [t.get("name", "") for t in agent.get("tools", [])]

        status_icon = "[ONLINE]" if status == "online" else "[offline]"

        print(f"{i}. {status_icon} {name}")
        print(f"   DID: {did[:30]}...")
        print(f"   Trust: {trust:.2f}")
        print(f"   Tools: {', '.join(tools) if tools else 'None'}")
        print()

    print(f"{'='*60}\n")
    return agents

if __name__ == "__main__":
    discover_agents()
