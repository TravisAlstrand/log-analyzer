from pathlib import Path
from loganalyzer.parsers.parser import parse_log


def load_logs(file_path: str):
    # NORMALIZE FILE PATH
    path = Path(file_path).expanduser().resolve()
    print(f"\nLoading & parsing {path}...\n")
    # PARSE LOG FILE
    return parse_log(path)
