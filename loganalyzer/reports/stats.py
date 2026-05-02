from loganalyzer.core.loader import load_logs
from datetime import datetime


def get_stats(file_path: str) -> list[str]:
    parsed_logs = load_logs(file_path)
    stats = compose_stats(parsed_logs)
    return stats


def compose_stats(logs: list[dict]) -> list[str]:
    stats = []
    stats.append("--- LOG FILE STATISTICS ---\n")
    stats.append("1. File Summary")
    stats.append(f"  - Total Events: {len(logs)}")
    timeframe = get_timeframe(logs)
    stats.append("2. Time Range")
    stats.append(f"  - {timeframe[0]} - {timeframe[1]}\n")

    return stats


def get_timeframe(logs: list[dict]) -> list[datetime | None]:
    earliest = None
    latest = None

    for log in logs:
        timestamp = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
        if earliest is None or timestamp < earliest:
            earliest = timestamp

        if latest is None or timestamp > latest:
            latest = timestamp

    return [earliest, latest]
