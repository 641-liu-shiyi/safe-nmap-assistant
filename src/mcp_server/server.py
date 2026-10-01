from mcp.server import MCPServer

from src.safe_scan import safe_scan


mcp = MCPServer("Safe Nmap Assistant")


@mcp.tool()
def safe_nmap_scan(
    target: str,
    port: int = 8080,
    profile: str = "basic"
) -> dict:
    """
    Run an authorized Nmap scan through the policy guard.

    Only approved targets, ports, and scan profiles are allowed.
    Unauthorized requests are rejected before Nmap executes.
    """

    result = safe_scan(
        target=target,
        port=port,
        profile=profile
    )

    return result


if __name__ == "__main__":
    mcp.run()