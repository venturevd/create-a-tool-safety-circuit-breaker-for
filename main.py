#!/usr/bin/env python3
"""
Tool Safety Circuit Breaker — Runtime protection for agent tool calls.

Monitors tool execution metrics and prevents calls when thresholds are crossed.

Usage:
    tool-circuit-breaker eval --policy policy.json --event event.json
    tool-circuit-breaker stream --policy policy.json --input telemetry.ndjson

See README.md for full documentation.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional, List, Dict
from collections import deque, defaultdict
import statistics


# ── Sensitive Data Patterns ────────────────────────────────────────────────────

DEFAULT_SENSITIVE_PATTERNS = [
    r'password\b', r'secret\b', r'key\b', r'token\b', r'credential\b',
    r'ssn\b', r'social.*security', r'credit.*card', r'card_number',
    r'api[_-]?key', r'auth[_-]?token', r'bearer', r'jwt',
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',  # JWT
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
    r'ghp_[0-9a-zA-Z]{36}',  # GitHub PAT
    r'xox[baprs]-[0-9a-zA-Z-]+',  # Slack tokens
]


def detect_sensitive_data(text: str, patterns: List[str]) -> List[str]:
    """Detect sensitive data patterns in a string. Returns list of matched pattern types."""
    matches = []
    text_lower = text.lower()
    for pattern in patterns:
        if re.search(pattern, text_lower, re.IGNORECASE):
            matches.append(pattern)
    return matches


def scan_data_for_sensitive(data: Any, patterns: List[str], path: str = "") -> List[str]:
    """Recursively scan data structures for sensitive information."""
    found = []
    if isinstance(data, dict):
        for key, value in data.items():
            full_path = f"{path}.{key}" if path else key
            # Check key
            key_matches = detect_sensitive_data(str(key), patterns)
            for m in key_matches:
                found.append(f"{full_path} (key): {m}")
            # Check value
            found.extend(scan_data_for_sensitive(value, patterns, full_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            found.extend(scan_data_for_sensitive(item, patterns, f"{path}[{i}]"))
    elif isinstance(data, str):
        matches = detect_sensitive_data(data, patterns)
        for m in matches:
            found.append(f"{path}: {m}")
    return found


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class CircuitBreakerPolicy:
    """Policy configuration for circuit breaker thresholds and actions."""
    # Failure rate thresholds
    failure_rate_threshold: float = 0.5  # 50% failures trips breaker
    failure_window_seconds: int = 60

    # Latency thresholds
    latency_p95_threshold_ms: int = 5000
    latency_window_seconds: int = 60

    # Replay diff thresholds (sandbox vs prod divergence)
    replay_diff_threshold: float = 0.1  # Average diff ratio > 10%
    replay_window_seconds: int = 300

    # Sensitive data detection
    sensitive_data_patterns: List[str] = field(default_factory=lambda: DEFAULT_SENSITIVE_PATTERNS)

    # Actions
    action_on_trip: str = "block"  # 'block', 'fallback', 'cooldown'
    cooldown_seconds: int = 300

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CircuitBreakerPolicy":
        """Load policy from dictionary."""
        return cls(
            failure_rate_threshold=float(data.get("failure_rate_threshold", 0.5)),
            failure_window_seconds=int(data.get("failure_window_seconds", 60)),
            latency_p95_threshold_ms=int(data.get("latency_p95_threshold_ms", 5000)),
            latency_window_seconds=int(data.get("latency_window_seconds", 60)),
            replay_diff_threshold=float(data.get("replay_diff_threshold", 0.1)),
            replay_window_seconds=int(data.get("replay_window_seconds", 300)),
            sensitive_data_patterns=list(data.get("sensitive_data_patterns", DEFAULT_SENSITIVE_PATTERNS)),
            action_on_trip=data.get("action_on_trip", "block"),
            cooldown_seconds=int(data.get("cooldown_seconds", 300)),
        )


@dataclass
class ToolEvent:
    """A single tool execution event."""
    tool: str
    timestamp: datetime
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    success: bool = True
    arguments: Dict[str, Any] = field(default_factory=dict)
    output: Any = None
    replay_diff: Optional[float] = None  # 0-1 divergence ratio from sandbox replay

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolEvent":
        """Create event from dictionary."""
        # Parse timestamp
        ts_str = data.get("timestamp", "")
        try:
            timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except (ValueError, TypeError):
            timestamp = datetime.now(timezone.utc)

        return cls(
            tool=data.get("tool", ""),
            timestamp=timestamp,
            duration_ms=data.get("duration_ms"),
            error=data.get("error"),
            success=data.get("success", True),
            arguments=data.get("arguments", {}),
            output=data.get("output"),
            replay_diff=data.get("replay_diff"),
        )


@dataclass
class CircuitState:
    """State tracking for a single tool's circuit breaker."""
    events: deque = field(default_factory=lambda: deque())
    tripped_until: Optional[datetime] = None
    trip_reason: Optional[str] = None
    trip_action: str = "block"

    def is_tripped(self) -> bool:
        """Check if circuit is currently tripped."""
        if self.tripped_until is None:
            return False
        return datetime.now(timezone.utc) < self.tripped_until

    def add_event(self, event: ToolEvent) -> None:
        """Add an event to history."""
        self.events.append(event)

    def prune_old(self, cutoff: datetime) -> None:
        """Remove events older than cutoff."""
        while self.events and self.events[0].timestamp < cutoff:
            self.events.popleft()

    def clear_trip(self) -> None:
        """Clear trip state."""
        self.tripped_until = None
        self.trip_reason = None
        self.trip_action = "block"

    def set_trip(self, action: str, reason: str, cooldown_seconds: int) -> None:
        """Trip the circuit."""
        self.trip_action = action
        self.trip_reason = reason
        self.tripped_until = datetime.now(timezone.utc) + timedelta(seconds=cooldown_seconds)


# ── Core Circuit Breaker Logic ────────────────────────────────────────────────

class ToolCircuitBreaker:
    """Circuit breaker manager for multiple tools."""

    def __init__(self, policy: CircuitBreakerPolicy):
        self.policy = policy
        self.states: Dict[str, CircuitState] = defaultdict(lambda: CircuitState())

    def _get_state(self, tool: str) -> CircuitState:
        """Get or create state for a tool."""
        return self.states[tool]

    def _calculate_failure_rate(self, state: CircuitState) -> Optional[float]:
        """Calculate failure rate over failure window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.policy.failure_window_seconds)
        state.prune_old(cutoff)

        if not state.events:
            return None

        recent = [e for e in state.events if e.timestamp >= cutoff]
        if not recent:
            return None

        failures = sum(1 for e in recent if not e.success)
        return failures / len(recent)

    def _calculate_latency_p95(self, state: CircuitState) -> Optional[float]:
        """Calculate p95 latency over latency window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.policy.latency_window_seconds)
        # Note: we don't prune here to keep events for failure rate, but we filter

        recent = [e.duration_ms for e in state.events
                  if e.timestamp >= cutoff and e.duration_ms is not None]
        if len(recent) < 10:  # Not enough data for reliable p95
            return None

        return statistics.quantiles(recent, n=20)[-1]  # 95th percentile

    def _calculate_avg_replay_diff(self, state: CircuitState) -> Optional[float]:
        """Calculate average replay divergence over replay window."""
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.policy.replay_window_seconds)
        recent = [e.replay_diff for e in state.events
                  if e.timestamp >= cutoff and e.replay_diff is not None]
        if not recent:
            return None
        return sum(recent) / len(recent)

    def check_sensitive_data(self, event: ToolEvent) -> List[str]:
        """Check for sensitive data in arguments or output."""
        found = []
        patterns = self.policy.sensitive_data_patterns

        # Check arguments
        if event.arguments:
            found.extend(scan_data_for_sensitive(event.arguments, patterns, "arguments"))

        # Check output
        if event.output:
            found.extend(scan_data_for_sensitive(event.output, patterns, "output"))

        return found

    def should_trip(self, event: ToolEvent) -> Dict[str, Any]:
        """
        Evaluate whether this event should trip the circuit breaker.

        Returns dict with keys:
        - trip: bool
        - action: 'block'|'fallback'|'cooldown'
        - reason: str (why it tripped, or empty if not tripped)
        """
        state = self._get_state(event.tool)

        # Check if currently tripped - if so, continue blocking regardless
        if state.is_tripped():
            return {
                "trip": True,
                "action": state.trip_action,
                "reason": f"Circuit still tripped: {state.trip_reason}",
                "cooldown_until": state.tripped_until.isoformat() if state.tripped_until else None,
            }

        # Record event first
        state.add_event(event)

        # 1. Sensitive data detection
        sensitive_findings = self.check_sensitive_data(event)
        if sensitive_findings:
            return {
                "trip": True,
                "action": "block",
                "reason": f"Sensitive data detected: {', '.join(sensitive_findings[:3])}",
            }

        # 2. Failure rate threshold
        failure_rate = self._calculate_failure_rate(state)
        if failure_rate is not None and failure_rate >= self.policy.failure_rate_threshold:
            state.set_trip(self.policy.action_on_trip,
                          f"High failure rate: {failure_rate:.1%} (threshold: {self.policy.failure_rate_threshold:.1%})",
                          self.policy.cooldown_seconds)
            return {
                "trip": True,
                "action": state.trip_action,
                "reason": state.trip_reason,
                "cooldown_until": state.tripped_until.isoformat() if state.tripped_until else None,
                "metric_failure_rate": failure_rate,
            }

        # 3. Latency p95 threshold
        latency_p95 = self._calculate_latency_p95(state)
        if latency_p95 is not None and latency_p95 >= self.policy.latency_p95_threshold_ms:
            state.set_trip(self.policy.action_on_trip,
                          f"High p95 latency: {latency_p95:.0f}ms (threshold: {self.policy.latency_p95_threshold_ms}ms)",
                          self.policy.cooldown_seconds)
            return {
                "trip": True,
                "action": state.trip_action,
                "reason": state.trip_reason,
                "cooldown_until": state.tripped_until.isoformat() if state.tripped_until else None,
                "metric_latency_p95_ms": latency_p95,
            }

        # 4. Replay diff threshold (sandbox/prod divergence)
        avg_diff = self._calculate_avg_replay_diff(state)
        if avg_diff is not None and avg_diff >= self.policy.replay_diff_threshold:
            state.set_trip(self.policy.action_on_trip,
                          f"High replay divergence: {avg_diff:.1%} (threshold: {self.policy.replay_diff_threshold:.1%})",
                          self.policy.cooldown_seconds)
            return {
                "trip": True,
                "action": state.trip_action,
                "reason": state.trip_reason,
                "cooldown_until": state.tripped_until.isoformat() if state.tripped_until else None,
                "metric_avg_replay_diff": avg_diff,
            }

        # All clear
        return {
            "trip": False,
            "action": "proceed",
            "reason": "",
        }


def should_trip_circuit_breaker(event: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate if a tool call event should trip the circuit breaker.

    This is the main library function. It takes an event dict and policy dict,
    and returns a decision with trip status, action, and reason.

    Args:
        event: Dict with keys:
            - tool: str (required)
            - timestamp: ISO 8601 string (required)
            - success: bool (optional, default True)
            - error: str (optional)
            - duration_ms: int (optional)
            - arguments: dict (optional)
            - output: any (optional)
            - replay_diff: float (optional, 0-1 divergence ratio)
        policy: Dict with policy configuration (see CircuitBreakerPolicy)

    Returns:
        Dict with keys:
        - trip: bool
        - action: 'block'|'fallback'|'cooldown'
        - reason: str
        - Optional metrics if tripped (metric_failure_rate, metric_latency_p95_ms, etc.)
    """
    # Parse policy
    policy_obj = CircuitBreakerPolicy.from_dict(policy)

    # Parse event
    event_obj = ToolEvent.from_dict(event)

    # Create breaker and evaluate (state is in-memory, so for single calls state is lost)
    # For library use, caller should manage the breaker instance to maintain state
    breaker = ToolCircuitBreaker(policy_obj)
    return breaker.should_trip(event_obj)


# ── CLI Implementation ─────────────────────────────────────────────────────────

def cmd_eval(args: argparse.Namespace) -> int:
    """Handle eval command: evaluate single event."""
    # Load policy
    try:
        with open(args.policy) as f:
            policy_data = json.load(f)
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        return 1

    # Load event
    try:
        with open(args.event) as f:
            event_data = json.load(f)
    except Exception as e:
        print(f"Error loading event: {e}", file=sys.stderr)
        return 1

    # Evaluate
    import time
    start = time.time()
    result = should_trip_circuit_breaker(event_data, policy_data)
    elapsed = (time.time() - start) * 1000

    # Output result
    print(json.dumps(result, indent=2))
    print(f"\n# Evaluation took {elapsed:.2f}ms", file=sys.stderr)

    return 0 if not result["trip"] else 1


def cmd_stream(args: argparse.Namespace) -> int:
    """Handle stream command: process NDJSON stream."""
    # Load policy
    try:
        with open(args.policy) as f:
            policy_data = json.load(f)
    except Exception as e:
        print(f"Error loading policy: {e}", file=sys.stderr)
        return 1

    # Create persistent breaker for this stream
    policy_obj = CircuitBreakerPolicy.from_dict(policy_data)
    breaker = ToolCircuitBreaker(policy_obj)

    # Open input stream
    if args.input == "-":
        infile = sys.stdin
        print("Reading events from stdin (NDJSON format)...", file=sys.stderr)
    else:
        try:
            infile = open(args.input, 'r')
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.input}", file=sys.stderr)
            return 1

    line_num = 0
    try:
        for line in infile:
            line_num += 1
            line = line.strip()
            if not line:
                continue

            try:
                event_data = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"Line {line_num}: Invalid JSON: {e}", file=sys.stderr)
                continue

            # Evaluate
            try:
                event_obj = ToolEvent.from_dict(event_data)
                result = breaker.should_trip(event_obj)
            except Exception as e:
                print(f"Line {line_num}: Error processing event: {e}", file=sys.stderr)
                result = {"trip": True, "action": "block", "reason": f"Processing error: {e}"}

            # Output result
            print(json.dumps(result))

            # Flush for streaming
            sys.stdout.flush()

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
    finally:
        if infile is not sys.stdin:
            infile.close()

    print(f"\nProcessed {line_num} events.", file=sys.stderr)
    return 0


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Tool Safety Circuit Breaker — Runtime protection for agent tool calls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Evaluate single event
  tool-circuit-breaker eval --policy policy.json --event event.json

  # Stream mode with file
  tool-circuit-breaker stream --policy policy.json --input telemetry.ndjson

  # Stream from stdin (omit --input to read from stdin)
  tail -f telemetry.ndjson | tool-circuit-breaker stream --policy policy.json
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run", required=True)

    # Eval command
    eval_parser = subparsers.add_parser(
        "eval",
        help="Evaluate a single event against policy"
    )
    eval_parser.add_argument(
        "--policy", "-p",
        type=Path,
        required=True,
        help="Path to policy JSON file"
    )
    eval_parser.add_argument(
        "--event", "-e",
        type=Path,
        required=True,
        help="Path to event JSON file"
    )

    # Stream command
    stream_parser = subparsers.add_parser(
        "stream",
        help="Process a stream of events from NDJSON"
    )
    stream_parser.add_argument(
        "--policy", "-p",
        type=Path,
        required=True,
        help="Path to policy JSON file"
    )
    stream_parser.add_argument(
        "--input", "-i",
        type=str,
        default="-",
        help="Input file (NDJSON) or '-' for stdin (default: -)"
    )

    args = parser.parse_args()

    if args.command == "eval":
        return cmd_eval(args)
    elif args.command == "stream":
        return cmd_stream(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
