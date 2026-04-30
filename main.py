import typer
from parser import parse_log
from detector import detect_failed_login_attempts, detect_suspicious_ips

app = typer.Typer()


@app.command()
def analyze(
    file: str,
    failed_logins: bool = False,
    suspicious_ips: bool = False
):
    parsed_logs = parse_log(file)

    if failed_logins:
        results = detect_failed_login_attempts(parsed_logs)
        print(f"--{len(results)} FAILED LOGIN ATTEMPTS DETECTED--")
        for result in results:
            print(result)
    elif suspicious_ips:
        results = []
        user_input = input("What is the threshold? (3 is default) ")

        if user_input.strip() == "":
            results = detect_suspicious_ips(parsed_logs)
        else:
            try:
                threshold = int(user_input)
                results = detect_suspicious_ips(parsed_logs, threshold)
            except ValueError:
                print("Not a valid threshold input. Using default of 3.")
                results = detect_suspicious_ips(parsed_logs)

        for result in results:
            print(result)
    else:
        print("--ALL LOGS--")
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
