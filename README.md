Tool Safety Circuit Breaker - CLI tool for runtime agent tool safety.

Usage:
  eval:  python3 main.py eval --policy policy.json --event event.json
  stream: python3 main.py stream --policy policy.json --input telemetry.ndjson
  stdin: tail -f telemetry.ndjson | python3 main.py stream --policy policy.json

Event JSON:
{"tool":"string","timestamp":"ISO8601","success":bool,"duration_ms":int,"arguments":{},"output":{},"replay_diff":float}

Policy JSON:
{"failure_rate_threshold":0.5,"failure_window_seconds":60,"latency_p95_threshold_ms":5000,"replay_diff_threshold":0.1,"action_on_trip":"block","cooldown_seconds":300}

Library:
from main import should_trip_circuit_breaker
result = should_trip_circuit_breaker(event_dict, policy_dict)

See help: python3 main.py --help
