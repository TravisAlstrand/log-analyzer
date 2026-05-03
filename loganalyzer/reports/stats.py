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
    stats.append("--- USER ACTIVITY SUMMARY ---\n")
    user_activities = get_user_activity(logs)
    for activity in user_activities:
        stats.append(activity)
    stats.append("--- IP ACTIVITY SUMMARY ---\n")
    ip_activities = get_ip_activity(logs)
    for activity in ip_activities:
        stats.append(activity)
    stats.append("--- AUTHENTICATION RATIO ---")
    successes, fails, ratio = get_auth_ratio(logs)
    stats.append(f"  - Successful Logins: {successes}")
    stats.append(f"  - Failed Logins: {fails}")
    stats.append(f"  - Failure Rate: {ratio:.2f}%")

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

    results.append("")
    return results


def get_user_activity(logs: list[dict]) -> list[str]:
    results = []
    user_activities = defaultdict(int)

    for log in logs:
        user = log["details"].get("user", "unknown")
        user_activities[user] += 1

    sorted_activities = dict(
        sorted(user_activities.items(), key=lambda item: item[1], reverse=True))

    for user, count in sorted_activities.items():
        results.append(f"  - {user}: {count} events")

    results.append("")
    return results


def get_ip_activity(logs: list[dict]) -> list[str]:
    results = []
    ip_activities = defaultdict(int)

    for log in logs:
        ip = log["details"].get("ip", "unknown")
        ip_activities[ip] += 1

    sorted_activities = dict(
        sorted(ip_activities.items(), key=lambda item: item[1], reverse=True))

    for ip, count in sorted_activities.items():
        results.append(f"  - {ip}: {count} events")

    results.append("")
    return results


def get_auth_ratio(logs: list[dict]) -> tuple[int, int, float]:
    successful_logins = 0
    failed_logins = 0
    failure_rate = 0

    for log in logs:
        if log["event"] == "SUCCESS_LOGIN":
            successful_logins += 1

        if log["event"] == "FAILED_LOGIN":
            failed_logins += 1

    total = failed_logins + successful_logins

    if total != 0:
        failure_rate = (failed_logins / total) * 100

    return successful_logins, failed_logins, failure_rate
