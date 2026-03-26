# Step 3: Create CLI for Circuit Breaker

**File to create:** `main.py`
**Estimated size:** ~200 lines

## Instructions

Write a Python script that implements a CLI tool with two commands: `eval` and `stream`. The `eval` command should take a policy and an event as JSON files and print the result of the `should_trip_circuit_breaker` function. The `stream` command should continuously read events and policies from the specified files and print the results. BUDGET: ≤50 LOC, 1 file only.

## Verification

Run: `python3 main.py --help`
