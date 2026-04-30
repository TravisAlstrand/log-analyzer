from collections import defaultdict


def detect_failed_login_attempts(logs: list):
    results = []

    for log in logs:
        if log["event"] == "FAILED_LOGIN":
            user = log["details"].get("user", "unknown")
            ip = log["details"].get("ip", "unknown")
            results.append(
                f"{log["timestamp"]} - Failed login for {user} from {ip}")

    return results


def detect_suspicious_ips(logs: list, threshold: int = 3):
    ip_count = defaultdict(int)

    for log in logs:
        ip = log["details"].get("ip")
        if ip:
            ip_count[ip] += 1

    suspicious_ips = []

    for ip, count in ip_count.items():
        if count >= threshold:
            suspicious_ips.append(f"{ip} triggered {count} events")

    return suspicious_ips
