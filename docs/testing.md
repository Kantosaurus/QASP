# QASP User Acceptance Testing Guide

This document covers every user-facing feature of the QASP authority server. Each section lists test scenarios, how to perform them, and what the expected result should be.

**Prerequisites**

- Python 3.10+
- Server running: `python scripts/qasp_server.py --host 127.0.0.1 --port 8080`
- Base URL: `http://localhost:8080`
- Tools: `curl`, Python `httpx`, or the `QASPClient` from `scripts/qasp_client.py`

---

## 1. Server Startup

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 1.1 | Server starts without error | Run `python scripts/qasp_server.py` | Server prints listening address; no tracebacks |
| 1.2 | Root info endpoint | `GET /` | 200 — JSON with `version`, `did`, `agent_count`, and `features` list |
| 1.3 | Features list | `GET /features` | 200 — Array of feature objects, each with `id`, `name`, `description` |
| 1.4 | Prometheus metrics | `GET /metrics` | 200 — Prometheus-format text (or 501 if `prometheus-client` not installed) |

---

## 2. Agent Registration

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 2.1 | Register a new agent | `POST /register` with body `{"name": "TestAgent", "tools": [{"name": "echo", "description": "Echoes input"}]}` | 200 — JSON with `agent_id`, `did` (starts with `did:qasp:`), `api_key`, `public_key` |
| 2.2 | Register with callback URL | Same as 2.1 but add `"callback_url": "http://localhost:9000/callback"` | 200 — Same fields; callback URL stored for tool-call relay |
| 2.3 | Register with no tools | `POST /register` with `{"name": "EmptyAgent", "tools": []}` | 200 — Agent created; should still have the `_messages` virtual tool |
| 2.4 | Register with missing name | `POST /register` with `{"tools": []}` | 400 or 422 — Validation error about missing `name` |
| 2.5 | Verify DID format | Check the `did` field from 2.1 | Format: `did:qasp:<base58btc-string>` |

---

## 3. Agent Update

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 3.1 | Update agent name | `PUT /agents/update` with header `X-API-Key: <api_key>` and body `{"name": "RenamedAgent"}` | 200 — Updated agent info with new name |
| 3.2 | Update tools list | `PUT /agents/update` with `{"tools": [{"name": "new_tool", "description": "New"}]}` | 200 — Old tools replaced; tokens for removed tools auto-revoked |
| 3.3 | Update callback URL | `PUT /agents/update` with `{"callback_url": "http://localhost:9001/cb"}` | 200 — Callback URL updated |
| 3.4 | Update without API key | `PUT /agents/update` with no `X-API-Key` header | 403 — Authentication error |
| 3.5 | Verify `_messages` tool preserved | After updating tools, check agent's tool list | `_messages` virtual tool is always present |

---

## 4. Agent Discovery

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 4.1 | Discover all agents | `GET /discover` with `X-API-Key` header | 200 — Array of agents with `did`, `name`, `tools`, `trust_score`, `endpoint` |
| 4.2 | Filter by capability | `GET /discover?capability=echo` | 200 — Only agents that have a tool matching "echo" |
| 4.3 | Filter by wildcard | `GET /discover?capability=*` | 200 — All agents returned |
| 4.4 | Filter by minimum trust | `GET /discover?min_trust=0.5` | 200 — Only agents with trust score >= 0.5 |
| 4.5 | Combined filters | `GET /discover?capability=echo&min_trust=0.3` | 200 — Agents matching both filters |
| 4.6 | No matches | `GET /discover?capability=nonexistent_tool` | 200 — Empty array |
| 4.7 | Without API key | `GET /discover` with no `X-API-Key` | 403 — Authentication error |

---

## 5. Token Management

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 5.1 | Request a capability token | `POST /tokens/request` with `{"target_did": "<did>", "tool_name": "echo"}` and `X-API-Key` | 200 — `token` (base64), `token_id`, `resource_uri`, `verbs`, `expires_at` |
| 5.2 | Request with specific verbs | Add `"verbs": ["exec", "read"]` to body | 200 — Token issued with requested verbs |
| 5.3 | Check token status (GOOD) | `GET /tokens/status/<token_id>` | 200 — Status `"GOOD"` |
| 5.4 | Revoke a token | `POST /tokens/revoke` with `{"token_id": "<token_id>"}` and `X-API-Key` | 200 — Confirmation with revoked token details |
| 5.5 | Check revoked token status | `GET /tokens/status/<token_id>` after revoking | 200 — Status `"REVOKED"` |
| 5.6 | Check unknown token | `GET /tokens/status/0000000000000000` | 200 — Status `"UNKNOWN"` |
| 5.7 | Request token for non-existent agent | Use a made-up DID | 404 — Agent not found |
| 5.8 | Request token for non-existent tool | Valid DID but tool name doesn't exist | 404 — Tool not found |
| 5.9 | Token expiry | Wait for token to expire (default 1 hour) or check `expires_at` field | `expires_at` is ~1 hour from issue time |

---

## 6. Tool Invocation

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 6.1 | Call a tool with valid token | `POST /tools/call` with `{"target_did": "<did>", "tool_name": "echo", "arguments": {"msg": "hello"}, "token": "<base64_token>"}` | 200 — `result` from target agent, plus `metering` (units, cost, currency) and `receipt_id` |
| 6.2 | Call with revoked token | Use a token that was revoked in test 5.4 | 403 — Token revoked error |
| 6.3 | Call with expired token | Use a token past its `expires_at` | 403 — Token expired error |
| 6.4 | Call wrong tool (scope mismatch) | Token issued for "echo" but call "other_tool" | 403 — Scope/resource mismatch |
| 6.5 | Call without token | Omit `token` from body | 400 — Missing token |
| 6.6 | Call without API key | Omit `X-API-Key` header | 403 — Authentication error |
| 6.7 | Verify metering recorded | After a successful call, check admin metering endpoint | Metering record exists with correct units and cost (10 credits per call) |
| 6.8 | Call agent with callback URL | Target agent has `callback_url` set | Server relays call to callback; result returned to caller |

---

## 7. Trust & Reputation

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 7.1 | Query trust score | `GET /trust/<did>` | 200 — `score` (0.0–1.0), `interaction_count`, `components` breakdown |
| 7.2 | New agent default trust | Query trust for a freshly registered agent | Score near 0.5 (neutral), interaction_count = 0 |
| 7.3 | Report success | `POST /trust/<did>/report` with `{"outcome": "success"}` and `X-API-Key` | 200 — Updated trust info; score should increase |
| 7.4 | Report failure | `POST /trust/<did>/report` with `{"outcome": "failure"}` | 200 — Updated trust info; score should decrease |
| 7.5 | Multiple successes raise score | Report 5 consecutive successes | Score progressively increases above 0.5 |
| 7.6 | Score components present | Check `components` field from 7.1 | Contains keys like `certification`, `reputation`, `behavioral`, `witness` |
| 7.7 | Query non-existent DID | `GET /trust/did:qasp:nonexistent` | 404 — Agent not found |

---

## 8. Conversations

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 8.1 | Open a conversation | `POST /conversations/open` with `{"target_did": "<did>"}` and `X-API-Key` | 200 — `conversation_id`, `token` (base64 messaging token), `resource_uri`, `participants`, `created_at` |
| 8.2 | Open with topic | Add `"topic": "Test discussion"` to body | 200 — Conversation created with topic |
| 8.3 | Send a message | `POST /messages/send` with `{"conversation_id": "<id>", "content": "Hello!", "token": "<messaging_token>"}` | 200 — `message_id`, `conversation_id`, `delivered` (true/false), `metering` (5 credits), `receipt_id` |
| 8.4 | Send with explicit intent | Add `"intent": "greeting"` to body | 200 — Message stored with intent = "greeting" |
| 8.5 | Send with auto-classified intent | Send "Hello there!" without `intent` field | 200 — Intent auto-classified as "greeting" |
| 8.6 | Reply to a message | Add `"reply_to": "<message_id>"` to body | 200 — Message linked as reply to referenced message |
| 8.7 | List conversations | `GET /conversations` with `X-API-Key` | 200 — Array of conversations this agent participates in |
| 8.8 | Filter by status | `GET /conversations?status=ACTIVE` | 200 — Only active conversations |
| 8.9 | Get messages | `GET /conversations/<id>/messages` with `X-API-Key` | 200 — `conversation_id`, `messages` array, `total` count |
| 8.10 | Get messages with `since` | `GET /conversations/<id>/messages?since=<ISO_timestamp>` | 200 — Only messages after that timestamp |
| 8.11 | Get messages with `limit` | `GET /conversations/<id>/messages?limit=5` | 200 — At most 5 messages |
| 8.12 | Get transcript | `GET /conversations/<id>/transcript` with `X-API-Key` | 200 — `conversation_id`, `topic`, `transcript` (formatted text), `message_count` |
| 8.13 | Close conversation | `POST /conversations/<id>/close` with `X-API-Key` | 200 — `status: "CLOSED"`, `closed_at`, `closed_by` |
| 8.14 | Send to closed conversation | Send message after closing | 403 or 400 — Conversation is closed |
| 8.15 | Non-participant access | Agent not in conversation tries to get messages | 403 — Not authorized |
| 8.16 | Trust gate | Agent with trust < 0.1 tries to open conversation | 403 — Trust score too low |

---

## 9. Inbox & Message Acknowledgement

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 9.1 | Poll inbox | `GET /messages/inbox` with `X-API-Key` | 200 — `messages` array of undelivered messages, `total` count |
| 9.2 | Inbox with limit | `GET /messages/inbox?limit=10` | 200 — At most 10 messages |
| 9.3 | Acknowledge message | `POST /messages/acknowledge` with `{"message_id": "<id>"}` | 200 — Confirmation; message marked as delivered |
| 9.4 | Acknowledged message gone from inbox | Poll inbox again after acknowledging | Previously acknowledged message no longer appears |
| 9.5 | Inbox empty when all delivered | Acknowledge all messages, then poll | 200 — Empty messages array |

---

## 10. WebSocket Real-Time

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 10.1 | Connect WebSocket | `ws://localhost:8080/ws?api_key=<api_key>` | Connected; receive `{"type": "connected", "agent_did": "...", "server_did": "...", "timestamp": "..."}` |
| 10.2 | Pending messages flushed | Have undelivered inbox messages, then connect WS | Pending messages delivered immediately after connection |
| 10.3 | Receive message push | Another agent sends a message while WS is open | Receive `{"type": "message", ...}` with message content |
| 10.4 | Receive conversation_opened | Another agent opens a conversation with you | Receive `{"type": "conversation_opened", ...}` |
| 10.5 | Receive tool_call | Another agent calls your tool | Receive `{"type": "tool_call", "request_id": "...", ...}` |
| 10.6 | Send tool_result | Respond with `{"type": "tool_result", "request_id": "...", "result": {...}}` | Server relays result back to caller |
| 10.7 | Receive token_revoked | One of your tokens is revoked | Receive `{"type": "token_revoked", ...}` |
| 10.8 | Receive trust_updated | Your trust score changes | Receive `{"type": "trust_updated", ...}` |
| 10.9 | Receive dispute_opened | A dispute is filed against you | Receive `{"type": "dispute_opened", ...}` |
| 10.10 | Ping/pong heartbeat | Send `{"type": "ping"}` | Receive `{"type": "pong"}` |
| 10.11 | Ack message | Send `{"type": "ack", "message_id": "<id>"}` | Message marked as delivered |
| 10.12 | Invalid API key | Connect with wrong `api_key` | Connection rejected or error message |

---

## 11. Dispute Resolution

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 11.1 | Open a dispute | `POST /disputes/open` with `{"respondent_did": "<did>", "type": "overcharge", "description": "Charged 20 credits instead of 10"}` and `X-API-Key` | 200 — `dispute_id`, `status: "OPEN"` |
| 11.2 | Get dispute status | `GET /disputes/<dispute_id>` | 200 — Full dispute record: claimant, respondent, type, status, description |
| 11.3 | Dispute against non-existent agent | Use a made-up DID | 404 — Agent not found |
| 11.4 | Dispute without API key | Omit `X-API-Key` | 403 — Authentication error |

---

## 12. Rate Limiting & Constraints

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 12.1 | Stay within rate limit | Make 10 tool calls within 60 seconds using same token | All calls succeed (200) |
| 12.2 | Exceed rate limit | Make 11+ tool calls within 60 seconds using same token | 429 — Rate limited (after exceeding 10 calls/60s default) |
| 12.3 | Rate limit resets | Wait 60 seconds after being rate limited, then try again | Call succeeds |
| 12.4 | Message rate limit | Send 30+ messages within 60 seconds on same messaging token | 429 — Rate limited (after exceeding 30 msgs/60s) |
| 12.5 | Message size limit | Send a message with content > 64 KB | 400 — Content too large |

---

## 13. Metering & Costs

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 13.1 | Tool call metering | Make a successful tool call, check `metering` in response | `units` present, `cost: 10`, `currency: "credits"` |
| 13.2 | Message metering | Send a message, check `metering` in response | `units` present, `cost: 5`, `currency: "credits"` |
| 13.3 | Receipt ID present | Check `receipt_id` in tool call or message response | Non-empty string; unique per operation |
| 13.4 | Admin metering records | `GET /admin/agents/<did>/metering` with `X-Admin-Key` | 200 — Array of metering records with timestamps, units, cost |
| 13.5 | Admin metering summary | `GET /admin/agents/<did>/metering/summary` with `X-Admin-Key` | 200 — `total_units`, `total_cost`, `total_calls`, `by_tool` breakdown |
| 13.6 | Filter metering by tool | `GET /admin/agents/<did>/metering?tool=echo` | 200 — Only records for the "echo" tool |

---

## 14. Admin Endpoints

All admin endpoints require `X-Admin-Key` header.

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 14.1 | List all agents | `GET /admin/agents` | 200 — Array of agents with `did`, `name`, `tools_count`, `tokens_issued`, `trust_score` |
| 14.2 | List all receipts | `GET /admin/receipts` | 200 — `records` array, `total` count |
| 14.3 | Filter receipts by agent | `GET /admin/receipts?agent_did=<did>` | 200 — Only records for that agent |
| 14.4 | List all tokens | `GET /admin/tokens` | 200 — Array of tokens with `token_id`, `subject_did`, `audience_did`, `resource_uri`, `status` |
| 14.5 | Filter tokens by status | `GET /admin/tokens?status=active` | 200 — Only active tokens |
| 14.6 | Token lifecycle history | `GET /admin/tokens/<token_id>/history` | 200 — `events` array (issued, revoked, etc.) |
| 14.7 | List all disputes | `GET /admin/disputes` | 200 — `disputes` array, `total` count |
| 14.8 | Filter disputes by status | `GET /admin/disputes?status=OPEN` | 200 — Only open disputes |
| 14.9 | Admin without key | Call any `/admin/*` endpoint without `X-Admin-Key` | 403 — Unauthorized |

---

## 15. Error Handling

| # | Test | Steps | Expected Result |
|---|------|-------|-----------------|
| 15.1 | Invalid API key | Use `X-API-Key: invalid_key_123` on any authenticated endpoint | 403 — `{"detail": "..."}` |
| 15.2 | Missing required field | `POST /register` with `{}` (no name) | 400 or 422 — Validation error |
| 15.3 | Agent not found | `GET /trust/did:qasp:does_not_exist` | 404 — Not found |
| 15.4 | Conversation not found | `GET /conversations/nonexistent_id/messages` | 404 — Not found |
| 15.5 | Invalid token format | `POST /tools/call` with `"token": "not_valid_base64!!!"` | 400 or 403 — Token decode/verification failure |
| 15.6 | Wrong HTTP method | `GET /register` instead of `POST /register` | 405 — Method not allowed |
| 15.7 | Malformed JSON body | Send invalid JSON to any POST endpoint | 400 or 422 — Parse error |

---

## 16. End-to-End Workflow

This test verifies the full lifecycle by chaining all features together.

| Step | Action | Expected Result |
|------|--------|-----------------|
| 1 | Start server | Server running on port 8080 |
| 2 | Register Agent A with tool "echo" | Receive `api_key_A`, `did_A` |
| 3 | Register Agent B with tool "summarize" | Receive `api_key_B`, `did_B` |
| 4 | Agent A discovers Agent B | Agent B appears in results with "summarize" tool |
| 5 | Agent A requests token for B's "summarize" tool | Receive valid token |
| 6 | Agent A calls B's "summarize" tool with token | 200 — Result returned with metering (10 credits) |
| 7 | Agent A reports success on B | B's trust score increases |
| 8 | Agent A opens conversation with B | Receive `conversation_id` and messaging token |
| 9 | Agent A sends message "Hello B!" | 200 — Message delivered, metering (5 credits) |
| 10 | Agent B polls inbox | Message from A appears |
| 11 | Agent B acknowledges message | Message marked delivered |
| 12 | Agent B sends reply | 200 — Reply delivered |
| 13 | Agent A gets transcript | Transcript shows both messages in order |
| 14 | Agent A closes conversation | Status changes to CLOSED |
| 15 | Agent A revokes the tool token | Token status changes to REVOKED |
| 16 | Agent A tries to call B's tool with revoked token | 403 — Token revoked |
| 17 | Admin checks metering summary for B | Shows 1 tool call (10 credits) + messages (5 credits each) |
| 18 | Agent A opens dispute against B | Dispute created with status OPEN |

---

## Quick Reference: HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad request (invalid params, malformed body) |
| 403 | Forbidden (bad API key, revoked token, trust gate, scope mismatch) |
| 404 | Not found (agent, tool, conversation, dispute) |
| 405 | Method not allowed |
| 422 | Validation error (missing required fields) |
| 429 | Rate limited |
| 501 | Dependency not available (e.g., prometheus-client) |
