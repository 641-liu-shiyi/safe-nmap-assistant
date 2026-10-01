import subprocess


def run_nmap_scan(target: str, port: int = 8080, service_detection: bool = False):
    command = [
        "nmap",
        "-sT",
        "-p",
        str(port)
    ]

    if service_detection:
        command.append("-sV")

    command.append(target)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30
        )

        return {
            "success": result.returncode == 0,
            "command": " ".join(command),
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "command": " ".join(command),
            "stdout": "",
            "stderr": "Nmap scan timed out."
        }


if __name__ == "__main__":
    scan_result = run_nmap_scan(
        target="127.0.0.1",
        port=8080,
        service_detection=True
    )

    print("Command:")
    print(scan_result["command"])

    print("\nSuccess:")
    print(scan_result["success"])

    print("\nNmap Output:")
    print(scan_result["stdout"])

    if scan_result["stderr"]:
        print("\nErrors:")
        print(scan_result["stderr"])