from loganalyzer.core.loader import load_logs


def get_stats(file_path: str) -> list[str]:
    stats = []
    parsed_logs = load_logs(file_path)

    stats.append("--- LOG FILE STATISTICS ---\n")
    stats.append("1. File Summary")
    stats.append(f"  - Total Events: {len(parsed_logs)}")

    return stats
