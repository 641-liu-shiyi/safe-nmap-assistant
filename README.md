# Safe AI-Assisted Network Reconnaissance

## A Policy-Constrained MCP Nmap Assistant

Course project for **CS/ECE 5584: Network Security** at Virginia Tech.

## Overview

This project demonstrates a safe AI-assisted network reconnaissance workflow for authorized targets.

The system allows a user to make a natural-language scan request without writing Nmap commands directly. The request is converted into a structured scan plan, passed through an MCP server, checked by an independent policy guard, and executed only if the request is authorized.

Unauthorized requests are rejected before Nmap execution.

## Architecture

User Natural-Language Request  
→ Agent / Planner  
→ MCP Client  
→ MCP Server  
→ Policy Guard  
→ Nmap Scanner  
→ Result Parser  
→ Readable Report

## Security Model

The AI agent is treated as untrusted.

The policy layer independently enforces:

- Approved targets only
- Approved ports only
- Approved scan profiles only
- Fail-closed behavior
- Scan timeout
- Controlled local test environment

The AI agent cannot directly execute arbitrary Nmap commands.

## Controlled Testbed

The project uses a Docker-based nginx target bound only to localhost:

```text
127.0.0.1:8080