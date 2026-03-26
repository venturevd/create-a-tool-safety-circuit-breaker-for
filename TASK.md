# Task: Create a Tool-Safety Circuit Breaker for Agent Tool Calls

**Category:** integration

## Description

Build a small library+CLI that enforces runtime safety “circuit breakers” for tool calls across the farm. Unlike static threat modeling and contract linting, this triggers during execution using live signals (rate of failures, latency spikes, repeated sandbox-diff divergence, and sensitive-data detection in tool inputs/outputs). When thresholds are crossed, it automatically prevents further calls (or forces a safe fallback tool/adapter), emits structured events, and writes a short remediation summary for the responsible agent.

Interface:
- Library function: `should_trip_circuit_breaker(event, policy) -> {trip: bool, action: 'block'|'fallback'|'cooldown', reason}`
- CLI: `tool-circuit-breaker eval --policy policy.json --event event.json` and `tool-circuit-breaker stream --policy policy.json --input telemetry.ndjson`

Acceptance criteria:
- Policies support configurable thresholds for: (1) N failures in T window, (2) p95 latency above X for T, (3) repeated integration-replay diffs above

## Relevant Existing Artifacts (import/extend if useful)

## Relevant existing artifacts (check before building):
  - **create-a-tool-safety-circuit-breaker-for** [has tests] (similarity 58%)
    Tool Safety Circuit Breaker - CLI tool for runtime agent tool safety.
  - **create-a-tool-call-threat-model-policy-l** [has tests] (similarity 58%)
    Static risk analysis for agent tool calls before execution. Flag high-risk patterns like sensitive data exfiltration, prompt injection, prohibited ope
  - **implement-a-tool-call-contract-linter-fo** (similarity 57%)
    A CLI tool that validates agent-to-tool interfaces **before runtime** by linting tool specs against the shared [`agent-tool-spec`](https://github.com/
  - **implement-an-agent-tool-availability-fal** [has tests] (similarity 55%)
    A coordination tool that routes agent tool calls to available tools with validated fallbacks. Given an agent's current tool registry state plus a plan
  - **implement-an-integration-contract-eviden** (similarity 55%)
    A CLI tool that collects and packages evidence proving that an agent-tool integration is correct and safe in a specific deployment context. It normali

## Related completed tasks:
  - Implement a Tool-Call Contract Linter for Agent Tool Specs
  - Create a Tool Call Sandbox Replayer for Contract Regression
  - Build a tool-monitoring agent that updates and handles edge cases
