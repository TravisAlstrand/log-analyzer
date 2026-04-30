def detect_failed_login_attempts(logs: list[dict]) -> list[str]:
    """
    Identify failed login attempts from parsed log data.

    This function scans structured log entries and extracts events where
    login attempts have failed. It returns a human-readable list of these
    events for reporting or further analysis.

    Args:
        logs (list[dict]):
            A list of parsed log entries. Each entry is expected to contain
            at least:
                - "timestamp" (str)
                - "event" (str)
                - "details" (dict) with optional keys like "user" and "ip"

    Returns:
        list[str]:
            A list of formatted strings describing each failed login attempt,
            including timestamp, user (if available), and source IP.
    """
    results = []

    for log in logs:
        if log["event"] == "FAILED_LOGIN":
            user = log["details"].get("user", "unknown")
            ip = log["details"].get("ip", "unknown")
            results.append(
                f"{log["timestamp"]} - Failed login for {user} from {ip}")

    return results
