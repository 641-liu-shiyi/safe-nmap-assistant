import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from src.agent.planner import plan_scan_request


async def run_agent(user_request: str):
    # Step 1: Convert natural language into a structured scan plan
    plan = plan_scan_request(user_request)

    print("\nUser Request:")
    print(user_request)

    print("\nGenerated Plan:")
    print(plan)

    # Step 2: Start and connect to the MCP server
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "src.mcp_server.server"]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Step 3: Call the policy-protected MCP tool
            result = await session.call_tool(
                "safe_nmap_scan",
                {
                    "target": plan["target"],
                    "port": plan["port"],
                    "profile": plan["profile"]
                }
            )

            print("\nMCP Result:")

            for content in result.content:
                if hasattr(content, "text"):
                    try:
                        parsed = json.loads(content.text)
                        print(json.dumps(parsed, indent=2))
                    except json.JSONDecodeError:
                        print(content.text)


if __name__ == "__main__":
    request = input(
        "Enter a network scan request: "
    )

    asyncio.run(
        run_agent(request)
    )