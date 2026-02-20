 # QASP + OpenClaw Integration Plan

 ## Goal

 Integrate QASP (post-quantum authenticated service protocol) with OpenClaw (LLM agent harness) to showcase secure agent-to-agent
 communication.

 ---
 Architecture Overview

 ┌─────────────────────────────────┐         ┌─────────────────────────────────┐
 │     OPENCLAW INSTANCE #1        │         │     OPENCLAW INSTANCE #2        │
 │                                 │         │                                 │
 │  ┌───────────────────────────┐  │         │  ┌───────────────────────────┐  │
 │  │   Claude/GPT Brain        │  │         │  │   Claude/GPT Brain        │  │
 │  └─────────────┬─────────────┘  │         │  └─────────────┬─────────────┘  │
 │                │                │         │                │                │
 │  ┌─────────────▼─────────────┐  │  QASP   │  ┌─────────────▼─────────────┐  │
 │  │   MCP Runtime             │  │  Shake  │  │   MCP Runtime             │  │
 │  │   ├── qasp-mcp-provider   │◄─┼─────────┼─►│   ├── qasp-mcp-provider   │  │
 │  │   └── other tools         │  │ (PQ+AES)│  │   └── other tools         │  │
 │  └───────────────────────────┘  │         │  └───────────────────────────┘  │
 │                                 │         │                                 │
 │  ┌───────────────────────────┐  │         │  ┌───────────────────────────┐  │
 │  │   QASP Agent Service      │  │         │  │   QASP Agent Service      │  │
 │  │   - did:qasp identity     │  │         │  │   - did:qasp identity     │  │
 │  │   - Capability tokens     │  │         │  │   - Token verification    │  │
 │  │   - Trust registry        │  │         │  │   - Usage metering        │  │
 │  │   tcp://127.0.0.1:18790   │  │         │  │   tcp://127.0.0.1:18791   │  │
 │  └───────────────────────────┘  │         │  └───────────────────────────┘  │
 └─────────────────────────────────┘         └─────────────────────────────────┘

 ---
 Integration Components

 1. QASP Agent Service (daemon)

 Runs alongside OpenClaw, provides:
 - QASP server listening on TCP port
 - DID identity management (did:qasp)
 - Capability token issuance/verification
 - Trust registry storage

 2. MCP Provider (qasp-mcp-provider)

 MCP server that OpenClaw loads, exposing QASP as tools:
 ┌──────────────────────────┬───────────────────────────────────────┐
 │         MCP Tool         │               Function                │
 ├──────────────────────────┼───────────────────────────────────────┤
 │ qasp_connect             │ Initiate QASP-Shake with remote agent │
 ├──────────────────────────┼───────────────────────────────────────┤
 │ qasp_request_capability  │ Request capability token for resource │
 ├──────────────────────────┼───────────────────────────────────────┤
 │ qasp_delegate_capability │ Attenuate and delegate token          │
 ├──────────────────────────┼───────────────────────────────────────┤
 │ qasp_invoke_tool         │ Call remote MCP tool via QASP channel │
 ├──────────────────────────┼───────────────────────────────────────┤
 │ qasp_check_trust         │ Query trust score for a DID           │
 ├──────────────────────────┼───────────────────────────────────────┤
 │ qasp_revoke_token        │ Revoke previously issued token        │
 └──────────────────────────┴───────────────────────────────────────┘
 3. OpenClaw Skill (qasp_skill)

 Installed in ~/.openclaw/workspace/skills/qasp_skill/:
 - Natural language interface for QASP operations
 - Automatic token management for workflows

 ---
 Files to Create
 ┌───────────────────────────────────────────────────┬───────────────────────────────────┐
 │                       Path                        │              Purpose              │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ src/qasp/bridges/openclaw/__init__.py             │ OpenClaw bridge package           │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ src/qasp/bridges/openclaw/mcp_server.py           │ MCP server exposing QASP as tools │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ src/qasp/bridges/openclaw/agent_service.py        │ QASP daemon for OpenClaw          │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ src/qasp/bridges/openclaw/config.py               │ Configuration loader              │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ src/qasp/bridges/openclaw/trust_policy.py         │ Trust-based access policies       │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ examples/openclaw_demo/scenario_1_direct.py       │ Direct tool call demo             │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ examples/openclaw_demo/scenario_2_delegation.py   │ Delegation chain demo             │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ examples/openclaw_demo/scenario_3_trust_gating.py │ Trust-gated access demo           │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ examples/openclaw_demo/scenario_4_multi_agent.py  │ Multi-agent collaboration         │
 ├───────────────────────────────────────────────────┼───────────────────────────────────┤
 │ examples/openclaw_demo/setup_openclaw.py          │ OpenClaw config helper            │
 └───────────────────────────────────────────────────┴───────────────────────────────────┘
 ---
 Configuration

 OpenClaw (~/.openclaw/openclaw.json)

 {
   "mcp_servers": {
     "qasp": {
       "command": "python",
       "args": ["-m", "qasp.bridges.openclaw.mcp_server"],
       "env": {
         "QASP_AGENT_SERVICE": "tcp://127.0.0.1:18790",
         "QASP_IDENTITY_PATH": "~/.openclaw/qasp/identity.json"
       }
     }
   }
 }

 QASP Identity (~/.openclaw/qasp/identity.json)

 {
   "did": "did:qasp:2ZTp9sZYQnVTQzGK8hA5zUQvZk7DhY4zRvJpPvjnL7bE",
   "keys": {
     "signing": {"algorithm": "ML-DSA-65", "path": "keys/signing.pem"},
     "kem": {"algorithm": "ML-KEM-768", "path": "keys/kem.pem"}
   },
   "endpoints": ["tcp://127.0.0.1:18790"]
 }

 ---
 Demo Scenarios

 Scenario 1: Direct QASP-Secured Tool Call

 Alpha connects to Beta via QASP-Shake, requests capability token, calls file_search tool through encrypted channel.

 Scenario 2: Capability Delegation Chain

 Owner issues token T0 to Alpha; Alpha attenuates to T1 for Gamma; Gamma presents chain [T0->T1] to server; server verifies T1 <= T0.

 Scenario 3: Trust-Gated Tool Access

 Sensitive tools require min trust score (e.g., 0.7). New agents denied until they build reputation through successful interactions.

 Scenario 4: Multi-Agent Collaboration

 Coordinator delegates attenuated tokens to Data Fetcher, Analyzer, and Report Writer. Each uses QASP to access their respective services.     

 ---
 Implementation Sequence

 Phase 1: Core Bridge (assumes QASP build plan complete)
 1. Create src/qasp/bridges/openclaw/ package structure
 2. Implement agent_service.py - QASP daemon with TCP listener
 3. Implement mcp_server.py - MCP tools exposing QASP operations
 4. Implement config.py - Load OpenClaw/QASP config
 5. Implement trust_policy.py - Tool access decisions based on trust

 Phase 2: Demo Scenarios
 6. Create examples/openclaw_demo/ with all 4 scenarios
 7. Create setup_openclaw.py helper script
 8. Write integration tests

 Phase 3: Packaging
 9. Create OpenClaw skill package for ~/.openclaw/workspace/skills/
 10. Add documentation for OpenClaw integration

 ---
 Verification

 1. Unit tests: Run pytest tests/bridges/test_openclaw.py
 2. Integration test: Start two OpenClaw instances, complete QASP-Shake, exchange encrypted messages
 3. Demo execution: Run each scenario in examples/openclaw_demo/
 4. Manual verification:
   - Check QASP logs show ML-KEM-768/ML-DSA-65 operations
   - Verify capability tokens are being issued/verified
   - Confirm trust scores update after interactions

 ---
 Critical Files (existing)

 - src/qasp/bridges/mcp_bridge.py - Base MCP bridge (needs list_tools(), call_tool())
 - src/qasp/protocol/capability.py - Token system (needs full implementation)
 - src/qasp/trust/scoring.py - Trust scorer (needs calculate())
 - src/qasp/protocol/connection.py - Sans-I/O connection (foundation)
 - src/qasp/transport/tcp.py - TCP transport (carries QASP traffic)