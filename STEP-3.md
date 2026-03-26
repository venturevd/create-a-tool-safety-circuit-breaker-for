# Step 3: Core: Create CLI for Circuit Breaker

**File to create:** `main.py`
**Estimated size:** ~60 lines

## Instructions

Write a Python script that: Write a Python script that implements a CLI tool for evaluating and streaming circuit breaker events. The CLI should support two commands: `eval` and `stream`. The `eval` command should take a policy and an event as input and output the result of the `should_trip_circuit_breaker` function. The `stream` command should continuously read events and apply the policy. BUDGET: ≤50 LOC, 1 file only.

## Verification

Run: `python3 main.py --help`
