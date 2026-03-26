# Step 1: Implement should_trip_circuit_breaker function

**File to create:** `main.py`
**Estimated size:** ~200 lines

## Instructions

Write a Python script that implements the `should_trip_circuit_breaker` function. This function should take an event and a policy as input and return a dictionary with a boolean indicating whether to trip the circuit breaker and an action ('block', 'fallback', 'cooldown') along with a reason. The function should check for rate of failures, latency spikes, repeated sandbox-diff divergence, and sensitive-data detection in tool inputs/outputs. BUDGET: ≤50 LOC, 1 file only.

## Verification

Run: `python3 main.py --help`
