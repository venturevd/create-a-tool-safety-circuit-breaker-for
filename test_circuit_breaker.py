#!/usr/bin/env python3
"""Quick test to verify circuit breaker functionality."""

import json
from datetime import datetime, timezone, timedelta
from main import ToolCircuitBreaker, CircuitBreakerPolicy, ToolEvent

def test_failure_rate_trip():
    """Test that high failure rate trips the breaker."""
    policy = CircuitBreakerPolicy(
        failure_rate_threshold=0.6,
        failure_window_seconds=60,
        action_on_trip="block",
        cooldown_seconds=60
    )
    breaker = ToolCircuitBreaker(policy)

    now = datetime.now(timezone.utc)

    # Send 8 failures and 2 successes = 80% failure rate
    for i in range(10):
        event = ToolEvent(
            tool="test_tool",
            timestamp=now - timedelta(seconds=10-i),  # within window
            success=i >= 8,  # First 8 are failures (i<8 => success=False)
            error="test error" if i < 8 else None,
            duration_ms=1000,
        )
        result = breaker.should_trip(event)

    print("After 10 events (8 failures, 2 successes):")
    print(json.dumps({
        "trip": result["trip"],
        "action": result["action"],
        "reason": result["reason"]
    }, indent=2))
    assert result["trip"], "Should trip on high failure rate"

def test_latency_trip():
    """Test that high p95 latency trips the breaker."""
    policy = CircuitBreakerPolicy(
        latency_p95_threshold_ms=2000,
        latency_window_seconds=60,
        action_on_trip="block",
        cooldown_seconds=60
    )
    breaker = ToolCircuitBreaker(policy)

    now = datetime.now(timezone.utc)

    # Send 15 events with latencies: 10 low (1000ms), 5 high (5000ms)
    # This should produce p95 ~4500ms, which exceeds 2000ms threshold
    for i in range(15):
        latency = 1000 if i < 10 else 5000
        event = ToolEvent(
            tool="slow_tool",
            timestamp=now - timedelta(seconds=20-i),
            success=True,
            duration_ms=latency,
        )
        result = breaker.should_trip(event)

    print("\nAfter 15 events (p95 ~4500ms, threshold 2000ms):")
    print(json.dumps({
        "trip": result["trip"],
        "action": result["action"],
        "reason": result["reason"]
    }, indent=2))
    assert result["trip"], "Should trip on high latency"

def test_sensitive_data_trip():
    """Test that sensitive data detection trips the breaker."""
    policy = CircuitBreakerPolicy(
        sensitive_data_patterns=["password", "api_key", "token"]
    )
    breaker = ToolCircuitBreaker(policy)

    now = datetime.now(timezone.utc)

    event = ToolEvent(
        tool="email_tool",
        timestamp=now,
        success=True,
        arguments={"body": "My password is secret123", "api_key": "sk-123"},
        output={"status": "sent"}
    )
    result = breaker.should_trip(event)

    print("\nEvent with sensitive data in arguments:")
    print(json.dumps({
        "trip": result["trip"],
        "action": result["action"],
        "reason": result["reason"]
    }, indent=2))
    assert result["trip"], "Should trip on sensitive data"
    assert "password" in result["reason"].lower() or "api_key" in result["reason"].lower()

def test_no_trip():
    """Test that normal operation does not trip."""
    policy = CircuitBreakerPolicy(
        failure_rate_threshold=0.5,
        latency_p95_threshold_ms=5000
    )
    breaker = ToolCircuitBreaker(policy)

    now = datetime.now(timezone.utc)

    # Send 20 successful events with normal latency
    for i in range(20):
        event = ToolEvent(
            tool="good_tool",
            timestamp=now - timedelta(seconds=30-i),
            success=True,
            duration_ms=500,
        )
        result = breaker.should_trip(event)

    print("\nAfter 20 successful events with low latency:")
    print(json.dumps({
        "trip": result["trip"],
        "action": result["action"],
        "reason": result["reason"]
    }, indent=2))
    assert not result["trip"], "Should not trip on healthy metrics"

if __name__ == "__main__":
    print("=== Tool Circuit Breaker Tests ===\n")
    try:
        test_failure_rate_trip()
        print("✓ Failure rate test passed")
    except AssertionError as e:
        print(f"✗ Failure rate test failed: {e}")

    try:
        test_latency_trip()
        print("✓ Latency test passed")
    except AssertionError as e:
        print(f"✗ Latency test failed: {e}")

    try:
        test_sensitive_data_trip()
        print("✓ Sensitive data test passed")
    except AssertionError as e:
        print(f"✗ Sensitive data test failed: {e}")

    try:
        test_no_trip()
        print("✓ No trip test passed")
    except AssertionError as e:
        print(f"✗ No trip test failed: {e}")

    print("\nAll tests completed!")
