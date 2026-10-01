import time
import json
from pathlib import Path
from src.safe_scan import safe_scan


TEST_CASES = [
    {
        "name": "Authorized basic scan",
        "target": "127.0.0.1",
        "port": 8080,
        "profile": "basic",
        "expected_allowed": True,
        "expected_executed": True,
        "expected_port": 8080,
    },
    {
        "name": "Authorized service detection",
        "target": "127.0.0.1",
        "port": 8080,
        "profile": "service_detection",
        "expected_allowed": True,
        "expected_executed": True,
        "expected_port": 8080,
    },
    {
        "name": "Unauthorized external target",
        "target": "8.8.8.8",
        "port": 8080,
        "profile": "basic",
        "expected_allowed": False,
        "expected_executed": False,
        "expected_port": None,
    },
    {
        "name": "Unauthorized port",
        "target": "127.0.0.1",
        "port": 22,
        "profile": "basic",
        "expected_allowed": False,
        "expected_executed": False,
        "expected_port": None,
    },
    {
        "name": "Unauthorized profile",
        "target": "127.0.0.1",
        "port": 8080,
        "profile": "aggressive",
        "expected_allowed": False,
        "expected_executed": False,
        "expected_port": None,
    },
]


def evaluate_test_case(test_case):
    start_time = time.perf_counter()

    result = safe_scan(
        target=test_case["target"],
        port=test_case["port"],
        profile=test_case["profile"],
    )

    latency = time.perf_counter() - start_time

    allowed_correct = (
        result["allowed"] == test_case["expected_allowed"]
    )

    executed_correct = (
        result["executed"] == test_case["expected_executed"]
    )

    port_correct = True

    if test_case["expected_port"] is not None:
        parsed_result = result.get("parsed_result", {})
        open_ports = parsed_result.get("open_ports", [])

        detected_ports = [
            item["port"]
            for item in open_ports
        ]

        port_correct = (
            test_case["expected_port"] in detected_ports
        )

    passed = (
        allowed_correct
        and executed_correct
        and port_correct
    )

    return {
        "name": test_case["name"],
        "passed": passed,
        "allowed": result["allowed"],
        "executed": result["executed"],
        "latency": latency,
        "reason": result["reason"],
    }


def main():
    results = []

    print("=" * 70)
    print("Safe Nmap Assistant Evaluation")
    print("=" * 70)

    for test_case in TEST_CASES:
        result = evaluate_test_case(test_case)
        results.append(result)

        print(f"\nTest: {result['name']}")
        print(f"Passed: {result['passed']}")
        print(f"Allowed: {result['allowed']}")
        print(f"Executed: {result['executed']}")
        print(f"Latency: {result['latency']:.3f} seconds")
        print(f"Reason: {result['reason']}")

    total_tests = len(results)

    passed_tests = sum(
        1 for result in results
        if result["passed"]
    )

    unauthorized_tests = [
        result
        for result in results
        if not result["allowed"]
    ]

    blocked_unauthorized = sum(
        1 for result in unauthorized_tests
        if not result["executed"]
    )

    block_rate = (
        blocked_unauthorized
        / len(unauthorized_tests)
        * 100
        if unauthorized_tests
        else 0
    )

    average_latency = sum(
        result["latency"]
        for result in results
    ) / total_tests

    print("\n" + "=" * 70)
    print("Evaluation Summary")
    print("=" * 70)

    print(
        f"Passed tests: "
        f"{passed_tests}/{total_tests}"
    )

    print(
        f"Unauthorized request block rate: "
        f"{block_rate:.1f}%"
    )

    print(
        f"Average latency: "
        f"{average_latency:.3f} seconds"
    )

    output = {
        "total_tests": total_tests,
        "passed_tests": passed_tests,
        "unauthorized_request_block_rate": block_rate,
        "average_latency_seconds": average_latency,
        "results": results,
    }

    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    output_file = results_dir / "evaluation_results.json"

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
        f"\nSaved evaluation results to: "
        f"{output_file}"
    )


if __name__ == "__main__":
    main()