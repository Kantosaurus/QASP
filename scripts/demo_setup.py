"""QASP Demo Setup  - One-command onboarding for demo participants.

Run:
    python demo_setup.py --server https://YOUR-SERVER-URL

This script:
  1. Checks Python version and installs dependencies (mcp, httpx)
  2. Downloads qasp_mcp_server.py if not present
  3. Tests connectivity to the QASP authority server
  4. Writes the MCP config for OpenClaw (or prints it for other clients)
  5. Prints instructions for the participant
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def check_python() -> None:
    v = sys.version_info
    print(f"[1/5] Python version: {v.major}.{v.minor}.{v.micro}", end="")
    if v >= (3, 10):
        print(" ... OK")
    else:
        print(" ... FAIL (need 3.10+)")
        sys.exit(1)


def install_deps() -> None:
    print("[2/5] Installing dependencies (mcp, httpx)...")
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--quiet", "mcp", "httpx"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print("      ... OK")


def ensure_mcp_server(server_url: str) -> Path:
    """Ensure qasp_mcp_server.py exists in the current directory."""
    local_path = Path("qasp_mcp_server.py")

    # Check if it's in the same directory as this script
    script_dir = Path(__file__).parent
    bundled = script_dir / "qasp_mcp_server.py"

    if local_path.exists():
        print(f"[3/5] MCP server script: {local_path.resolve()} ... OK")
        return local_path.resolve()
    elif bundled.exists():
        print(f"[3/5] MCP server script: {bundled.resolve()} ... OK")
        return bundled.resolve()
    else:
        print(f"[3/5] qasp_mcp_server.py not found.")
        print("      Place qasp_mcp_server.py in the current directory and re-run.")
        sys.exit(1)


def test_server(server_url: str) -> None:
    print(f"[4/5] Testing connection to {server_url} ...")
    try:
        import httpx
        resp = httpx.get(f"{server_url.rstrip('/')}/", timeout=10)
        data = resp.json()
        print(f"      Server: {data.get('name', '?')} v{data.get('version', '?')}")
        print(f"      DID:    {data.get('did', '?')}")
        print(f"      Agents: {data.get('agents_registered', '?')} registered")
        print("      ... OK")
    except Exception as e:
        print(f"      ... FAIL: {e}")
        print()
        print("      Make sure the QASP authority server is running at that URL.")
        print("      If it's on a different address, use: python demo_setup.py --server <URL>")
        sys.exit(1)


def write_mcp_config(server_url: str, mcp_server_path: Path, client: str) -> None:
    print(f"[5/5] Configuring MCP for {client}...")

    mcp_config = {
        "mcpServers": {
            "qasp": {
                "command": sys.executable,
                "args": [
                    str(mcp_server_path),
                    "--server", server_url,
                ],
            }
        }
    }

    if client == "openclaw":
        # OpenClaw uses ~/.openclaw/mcp.json
        config_dir = Path.home() / ".openclaw"
        config_file = config_dir / "mcp.json"

        # Merge with existing config if present
        existing: dict = {}
        if config_file.exists():
            try:
                existing = json.loads(config_file.read_text())
            except Exception:
                pass

        if "mcpServers" not in existing:
            existing["mcpServers"] = {}
        existing["mcpServers"]["qasp"] = mcp_config["mcpServers"]["qasp"]

        config_dir.mkdir(parents=True, exist_ok=True)
        config_file.write_text(json.dumps(existing, indent=2))
        print(f"      Wrote: {config_file}")

    elif client == "claude-code":
        # Claude Code uses .mcp.json in the project directory
        config_file = Path(".mcp.json")
        existing: dict = {}
        if config_file.exists():
            try:
                existing = json.loads(config_file.read_text())
            except Exception:
                pass

        if "mcpServers" not in existing:
            existing["mcpServers"] = {}
        existing["mcpServers"]["qasp"] = mcp_config["mcpServers"]["qasp"]

        config_file.write_text(json.dumps(existing, indent=2))
        print(f"      Wrote: {config_file}")

    elif client == "claude-desktop":
        # Claude Desktop uses platform-specific config
        if platform.system() == "Windows":
            config_dir = Path(os.environ.get("APPDATA", "")) / "Claude"
        elif platform.system() == "Darwin":
            config_dir = Path.home() / "Library" / "Application Support" / "Claude"
        else:
            config_dir = Path.home() / ".config" / "claude"

        config_file = config_dir / "claude_desktop_config.json"
        existing: dict = {}
        if config_file.exists():
            try:
                existing = json.loads(config_file.read_text())
            except Exception:
                pass

        if "mcpServers" not in existing:
            existing["mcpServers"] = {}
        existing["mcpServers"]["qasp"] = mcp_config["mcpServers"]["qasp"]

        config_dir.mkdir(parents=True, exist_ok=True)
        config_file.write_text(json.dumps(existing, indent=2))
        print(f"      Wrote: {config_file}")

    else:
        # Generic  - just print the config
        print("      Add this to your MCP client config:")
        print()
        print(json.dumps(mcp_config, indent=2))

    print("      ... OK")


def print_instructions(client: str) -> None:
    print()
    print("=" * 64)
    print("  SETUP COMPLETE")
    print("=" * 64)
    print()
    print("  Open your agent and tell it something like:")
    print()
    print('    "Register me as \'Alice\' on the QASP network.')
    print('     I\'m selling a tool called \'summarize\' that')
    print('     summarizes text. Find other agents and see')
    print('     what tools are available."')
    print()
    print("  The agent will use the QASP tools automatically to:")
    print("    1. Register you  (qasp_register)")
    print("    2. Find peers    (qasp_discover)")
    print("    3. Get tokens    (qasp_request_token)")
    print("    4. Call tools    (qasp_call_tool)")
    print()
    print("  Quick prompts to try:")
    print()
    print('    "What agents are on the network?"')
    print('    "Call the echo tool on <agent name>"')
    print('    "What\'s the trust score of <agent DID>?"')
    print('    "Revoke the token I just used"')
    print()

    if client != "manual":
        print(f"  Restart {client} to load the new MCP config.")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="QASP Demo Setup - one-command onboarding",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo_setup.py --server http://192.168.1.50:8080
  python demo_setup.py --server https://qasp.example.com --client claude-code
  python demo_setup.py --server http://localhost:8080 --client manual
        """,
    )
    parser.add_argument(
        "--server",
        default="http://localhost:8080",
        help="QASP Authority Server URL (default: http://localhost:8080)",
    )
    parser.add_argument(
        "--client",
        choices=["openclaw", "claude-code", "claude-desktop", "manual"],
        default="openclaw",
        help="Which MCP client to configure (default: openclaw)",
    )
    args = parser.parse_args()

    print()
    print("  QASP Demo Setup")
    print("  ===============")
    print()

    check_python()
    install_deps()
    mcp_path = ensure_mcp_server(args.server)
    test_server(args.server)
    write_mcp_config(args.server, mcp_path, args.client)
    print_instructions(args.client)


if __name__ == "__main__":
    main()
