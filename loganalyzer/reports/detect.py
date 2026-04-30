from loganalyzer.core.loader import load_logs
from loganalyzer.detectors.failed_logins import detect_failed_login_attempts
from loganalyzer.detectors.suspicious_ips import detect_suspicious_ips


def run_detection(file_path: str, failed_logins: bool, suspicious_ips: bool, all: bool) -> list[str]:
    parsed_logs = load_logs(file_path)
    results = []

    if failed_logins or all:
        results.append("--- FAILED LOGIN ATTEMPTS ---")
        results.extend(detect_failed_login_attempts(parsed_logs))
        results.append("")
    if suspicious_ips or all:
        results.append("--- SUSPICIOUS IPs ---")
        results.extend(detect_suspicious_ips(parsed_logs))
        results.append("")

    return results
