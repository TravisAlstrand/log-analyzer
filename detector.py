def detect_failed_login_attempts(logs: list):
    results = []

    for log in logs:
        if log["event"] == "FAILED_LOGIN":
            user = log["details"].get("user", "unknown")
            ip = log["details"].get("ip", "unknown")
            results.append(
                f"{log["timestamp"]} - Failed login for {user} from {ip}")

    return results
