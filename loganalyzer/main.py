from loganalyzer.reports.detect import run_detection
from loganalyzer.reports.stats import get_stats
import typer

app = typer.Typer()


@app.command()
def detect(
    file: str,
    failed_logins: bool = False,
    suspicious_ips: bool = False,
    all: bool = False
):
    results = run_detection(file, failed_logins, suspicious_ips, all)

    for item in results:
        print(item)


@app.command()
def stats(file: str):
    stats = get_stats(file)

    for stat in stats:
        print(stat)


if __name__ == "__main__":
    app()
