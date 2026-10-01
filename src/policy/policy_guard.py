ALLOWED_TARGETS = {
    "127.0.0.1"
}

ALLOWED_PORTS = {
    8080
}

ALLOWED_PROFILES = {
    "basic",
    "service_detection"
}


def check_policy(target: str, port: int, profile: str):
    if target not in ALLOWED_TARGETS:
        return {
            "allowed": False,
            "reason": f"Target '{target}' is not in the approved allowlist."
        }

    if port not in ALLOWED_PORTS:
        return {
            "allowed": False,
            "reason": f"Port '{port}' is not approved."
        }

    if profile not in ALLOWED_PROFILES:
        return {
            "allowed": False,
            "reason": f"Scan profile '{profile}' is not approved."
        }

    return {
        "allowed": True,
        "reason": "Request passed policy validation."
    }


if __name__ == "__main__":
    tests = [
        {
            "target": "127.0.0.1",
            "port": 8080,
            "profile": "basic"
        },
        {
            "target": "8.8.8.8",
            "port": 8080,
            "profile": "basic"
        },
        {
            "target": "127.0.0.1",
            "port": 22,
            "profile": "basic"
        },
        {
            "target": "127.0.0.1",
            "port": 8080,
            "profile": "aggressive"
        }
    ]

    for test in tests:
        result = check_policy(
            target=test["target"],
            port=test["port"],
            profile=test["profile"]
        )

        print("\nRequest:")
        print(test)

        print("Allowed:")
        print(result["allowed"])

        print("Reason:")
        print(result["reason"])