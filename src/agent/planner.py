def plan_scan_request(user_request: str) -> dict:
    """
    Convert a simple natural-language request into
    an approved scan plan.

    This deterministic planner is used as a fallback
    when an LLM/API is unavailable.
    """

    text = user_request.lower().strip()

    plan = {
        "target": "127.0.0.1",
        "port": 8080,
        "profile": "basic"
    }

    # User asks for service/version information
    service_keywords = [
        "service",
        "services",
        "version",
        "versions",
        "what is running",
        "what's running",
        "exposed",
        "identify"
    ]

    if any(keyword in text for keyword in service_keywords):
        plan["profile"] = "service_detection"

    return plan


if __name__ == "__main__":
    tests = [
        "Scan my approved web server.",
        "Scan my approved web server and identify the service.",
        "Tell me what is exposed on the approved server.",
        "Check what version is running."
    ]

    for request in tests:
        result = plan_scan_request(request)

        print("\nUser request:")
        print(request)

        print("Generated plan:")
        print(result)