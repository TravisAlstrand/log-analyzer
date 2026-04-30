from loganalyzer.reports.detect import run_detection
import typer

app = typer.Typer()


@app.command()
def detect(
    file: str,
    failed_logins: bool = False,
    suspicious_ips: bool = False,
):
    results = run_detection(file, failed_logins, suspicious_ips)

    for item in results:
        print(item)


if __name__ == "__main__":
    app()
