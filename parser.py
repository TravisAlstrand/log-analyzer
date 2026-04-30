def parse_log(filepath):
    logs = []

    with open(filepath, "r") as log_file:
        for log in log_file:
            parts = log.strip().split()

            log_entry = {
                "timestamp": f"{parts[0]} {parts[1]}",
                "event": parts[2],
                "details": {}
            }

            for item in parts[3:]:
                if "=" in item:
                    key, value = item.split("=")
                    log_entry["details"][key] = value

            logs.append(log_entry)

    return logs
