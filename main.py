import typer
from parser import parse_log
from detector import detect_failed_login_attempts

app = typer.Typer()


@app.command()
def analyze(
    file: str,
    failed_logins: bool = False,
    suspicious_ip: bool = False
):
    parsed_logs = parse_log(file)

    if (failed_logins):
        results = detect_failed_login_attempts(parsed_logs)
        print(f"--{len(results)} FAILED LOGIN ATTEMPTS DETECTED--")
        for result in results:
            print(result)
    else:
        print(f"--ALL LOGS--")
        for log in parsed_logs:
            for key, value in log.items():
                if key == "details":
                    print("details")
                    for d_key, d_value in value.items():
                        print(f"  {d_key}: {d_value}")
                else:
                    print(f"{key}: {value}")
            print("----------------------\n")


if __name__ == "__main__":
    app()
