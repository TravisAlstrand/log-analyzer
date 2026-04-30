from loganalyzer.detectors.failed_logins import detect_failed_login_attempts
from loganalyzer.detectors.suspicious_ips import detect_suspicious_ips
from loganalyzer.core.loader import load_logs


def run_detection(file_path: str, failed_logins: bool, suspicious_ips: bool) -> list[str]:
    parsed_logs = load_logs(file_path)
    results = []

    if failed_logins:
        results.extend(detect_failed_login_attempts(parsed_logs))
    if suspicious_ips:
        results.extend(detect_suspicious_ips(parsed_logs))

    return results
