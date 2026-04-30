from collections import defaultdict


def detect_suspicious_ips(logs: list[dict], threshold: int = 3) -> list[str]:
    """
    Detect IP addresses with unusually high activity.

    This function counts how many log events originate from each IP address
    and flags IPs that exceed a defined threshold. It is useful for identifying
    potential brute-force attempts or abnormal network behavior.

    Args:
        logs (list[dict]):
            A list of parsed log entries. Each entry is expected to contain
            a "details" dictionary with an "ip" key when applicable.

        threshold (int, optional):
            The minimum number of events from a single IP required to flag it
            as suspicious. Defaults to 3.

    Returns:
        list[str]:
            A list of formatted strings describing suspicious IP addresses
            and their corresponding event counts.
    """
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
