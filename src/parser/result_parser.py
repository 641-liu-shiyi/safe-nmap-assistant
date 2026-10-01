import re


def parse_nmap_output(nmap_output: str) -> dict:
    """
    Parse Nmap text output into a simple structured report.
    """

    report = {
        "open_ports": [],
        "summary": ""
    }

    if not nmap_output:
        report["summary"] = "No Nmap output was returned."
        return report

    lines = nmap_output.splitlines()

    for line in lines:
        line = line.strip()

        # Example:
        # 8080/tcp open http nginx 1.31.6
        match = re.match(
            r"^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?$",
            line
        )

        if match:
            port = int(match.group(1))
            service = match.group(2)
            version = match.group(3) or ""

            report["open_ports"].append(
                {
                    "port": port,
                    "protocol": "tcp",
                    "service": service,
                    "version": version
                }
            )

    if report["open_ports"]:
        ports = ", ".join(
            str(item["port"])
            for item in report["open_ports"]
        )

        report["summary"] = (
            f"Scan completed successfully. "
            f"Detected open TCP port(s): {ports}."
        )
    else:
        report["summary"] = (
            "Scan completed, but no open TCP ports were detected "
            "in the approved scan scope."
        )

    return report


def build_readable_report(
    target: str,
    parsed_result: dict
) -> str:
    """
    Convert structured scan results into a human-readable report.
    """

    lines = [
        "Authorized Network Scan Report",
        f"Target: {target}",
        ""
    ]

    open_ports = parsed_result.get("open_ports", [])

    if not open_ports:
        lines.append("No open ports were detected.")
    else:
        lines.append("Detected Services:")

        for item in open_ports:
            service_line = (
                f"- Port {item['port']}/{item['protocol']}: "
                f"{item['service']}"
            )

            if item["version"]:
                service_line += f" ({item['version']})"

            lines.append(service_line)

    lines.append("")
    lines.append("Summary:")
    lines.append(parsed_result.get("summary", ""))

    return "\n".join(lines)


if __name__ == "__main__":
    sample_output = """
PORT     STATE SERVICE VERSION
8080/tcp open  http    nginx 1.31.6
"""

    parsed = parse_nmap_output(sample_output)

    print("Parsed result:")
    print(parsed)

    print("\nReadable report:")
    print(
        build_readable_report(
            target="127.0.0.1",
            parsed_result=parsed
        )
    )