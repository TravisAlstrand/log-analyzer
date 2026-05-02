from loganalyzer.core.loader import load_logs
from datetime import datetime
from collections import defaultdict


def get_stats(file_path: str) -> list[str]:
    parsed_logs = load_logs(file_path)
    stats = compose_stats(parsed_logs)
    return stats


def compose_stats(logs: list[dict]) -> list[str]:
    stats = []
    stats.append("--- LOG FILE STATISTICS ---\n")
    stats.append("1. File Summary")
    stats.append(f"  - Total Events: {len(logs)}")
    earliest, latest = get_timeframe(logs)
    stats.append("2. Time Range")
    stats.append(f"  - {earliest} - {latest}\n")
    stats.append("--- EVENT TYPE BREAKDOWN ---\n")
    event_types = get_event_counts(logs)
    for event in event_types:
        stats.append(event)

    return stats


def get_timeframe(logs: list[dict]) -> tuple[datetime | None, datetime | None]:
    earliest = None
    latest = None

    for log in logs:
        timestamp = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        if earliest is None or timestamp < earliest:
            earliest = timestamp

        if latest is None or timestamp > latest:
            latest = timestamp

    return earliest, latest


def get_event_counts(logs: list[dict]) -> list[str]:
    results = []
    event_count = defaultdict(int)

    for log in logs:
        event = log["event"]
        event_count[event] += 1

    for event, count in event_count.items():
        results.append(f"  - {event}: {count}")

    return results
