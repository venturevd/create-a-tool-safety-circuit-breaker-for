# Step 1: Core: Create Circuit Breaker Library

**File to create:** `main.py`
**Estimated size:** ~60 lines

## Instructions

Write a Python script that: Write a Python script that implements the `should_trip_circuit_breaker` function. This function should take an event and a policy as input and return a dictionary with keys 'trip' and 'action' based on the event data and policy thresholds. The function should check for rate of failures, latency spikes, repeated sandbox-diff divergence, and sensitive-data detection in tool inputs/outputs. BUDGET: ≤50 LOC, 1 file only.

## Verification

Run: `python3 main.py --help`
