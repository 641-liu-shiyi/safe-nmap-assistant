from src.policy.policy_guard import check_policy
from src.scanner.nmap_scanner import run_nmap_scan
from src.parser.result_parser import parse_nmap_output, build_readable_report


def safe_scan(target: str, port: int, profile: str):
    policy_result = check_policy(
        target=target,
        port=port,
        profile=profile
    )

    if not policy_result["allowed"]:
        return {
            "executed": False,
            "allowed": False,
            "reason": policy_result["reason"],
            "scan_result": None
        }

    service_detection = profile == "service_detection"

    scan_result = run_nmap_scan(
        target=target,
        port=port,
        service_detection=service_detection
    )

    parsed_result = parse_nmap_output(
        scan_result["stdout"]
    )

    readable_report = build_readable_report(
        target=target,
        parsed_result=parsed_result
    )

    return {
        "executed": True,
        "allowed": True,
        "reason": policy_result["reason"],
        "scan_result": scan_result,
        "parsed_result": parsed_result,
        "readable_report": readable_report
    }


if __name__ == "__main__":
    tests = [
        {
            "name": "Authorized basic scan",
            "target": "127.0.0.1",
            "port": 8080,
            "profile": "basic"
        },
        {
            "name": "Unauthorized external target",
            "target": "8.8.8.8",
            "port": 8080,
            "profile": "basic"
        },
        {
            "name": "Unauthorized port",
            "target": "127.0.0.1",
            "port": 22,
            "profile": "basic"
        },
        {
            "name": "Authorized service detection",
            "target": "127.0.0.1",
            "port": 8080,
            "profile": "service_detection"
        }
    ]

    for test in tests:
        print("\n" + "=" * 60)
        print(test["name"])
        print("=" * 60)

        result = safe_scan(
            target=test["target"],
            port=test["port"],
            profile=test["profile"]
        )

        print("Allowed:", result["allowed"])
        print("Executed:", result["executed"])
        print("Reason:", result["reason"])

        if result["scan_result"]:
            print("\nCommand:")
            print(result["scan_result"]["command"])

            print("\nNmap Output:")
            print(result["scan_result"]["stdout"])

            print("\nParsed Result:")
            print(result["parsed_result"])

            print("\nReadable Report:")
            print(result["readable_report"])