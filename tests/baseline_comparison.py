import subprocess
import json
from pathlib import Path
from src.safe_scan import safe_scan
from src.parser.result_parser import parse_nmap_output


def run_manual_baseline():
    command = [
        "nmap",
        "-sT",
        "-sV",
        "-p",
        "8080",
        "127.0.0.1",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=30,
    )

    return {
        "success": result.returncode == 0,
        "command": " ".join(command),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def main():
    print("=" * 70)
    print("Manual Baseline Comparison")
    print("=" * 70)

    # Step 1: Manual Nmap baseline
    baseline = run_manual_baseline()

    print("\nManual baseline command:")
    print(baseline["command"])

    baseline_parsed = parse_nmap_output(
        baseline["stdout"]
    )

    # Step 2: Safe Nmap Assistant
    assistant_result = safe_scan(
        target="127.0.0.1",
        port=8080,
        profile="service_detection",
    )

    assistant_parsed = assistant_result[
        "parsed_result"
    ]

    print("\nManual baseline parsed result:")
    print(baseline_parsed)

    print("\nAssistant parsed result:")
    print(assistant_parsed)

    # Step 3: Compare open ports
    baseline_ports = {
        item["port"]
        for item in baseline_parsed["open_ports"]
    }

    assistant_ports = {
        item["port"]
        for item in assistant_parsed["open_ports"]
    }

    port_match = (
        baseline_ports == assistant_ports
    )

    # Step 4: Compare service information
    baseline_services = {
        (
            item["port"],
            item["service"],
            item["version"],
        )
        for item in baseline_parsed["open_ports"]
    }

    assistant_services = {
        (
            item["port"],
            item["service"],
            item["version"],
        )
        for item in assistant_parsed["open_ports"]
    }

    service_match = (
        baseline_services == assistant_services
    )

    overall_match = (
        port_match and service_match
    )

    print("\n" + "=" * 70)
    print("Comparison Summary")
    print("=" * 70)

    print(
        f"Port match: {port_match}"
    )

    print(
        f"Service/version match: "
        f"{service_match}"
    )

    print(
        f"Overall baseline match: "
        f"{overall_match}"
    )

    output = {
        "manual_baseline_command": baseline["command"],
        "manual_baseline_success": baseline["success"],
        "manual_baseline_parsed_result": baseline_parsed,
        "assistant_parsed_result": assistant_parsed,
        "port_match": port_match,
        "service_version_match": service_match,
        "overall_baseline_match": overall_match,
    }

    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    output_file = results_dir / "baseline_results.json"

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            output,
            file,
            indent=2
        )

    print(
        f"\nSaved baseline results to: "
        f"{output_file}"
    )


if __name__ == "__main__":
    main()