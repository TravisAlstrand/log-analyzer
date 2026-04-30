import typer
from parser import parse_log

app = typer.Typer()


@app.command()
def analyze(
    file: str,
    failed_logins: bool = False,
    suspicious_ip: bool = False
):
    logs = parse_log(file)
    for log in logs:
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
