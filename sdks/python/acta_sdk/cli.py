"""CLI for Acta SDK & Global Git-Aware MCP Setup (`acta-sdk` / `acta-mcp`).

Commands:
    acta-mcp setup --master-key <KEY> [--default-tenant ardyn-intelligence]
    acta-mcp status
    acta-mcp serve
    acta-mcp mint-key <tenant_id>
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .client import DEFAULT_CLOUDRUN_URL
from .crypto import mint_tenant_api_key
from .mcp_bridge import (
    DEFAULT_LIVE_HOST_PUBKEY,
    ActaGitMcpBridge,
    install_global_mcp_configs,
    load_credentials,
    resolve_git_workspace_context,
    save_credentials,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Acta Compiler CLI & Git-Aware Global MCP Bridge")
    sub = parser.add_subparsers(dest="cmd", required=True)

    setup_p = sub.add_parser(
        "setup",
        help="Store credentials once (~/.config/acta/credentials.json) & wire Claude, Gemini CLI, and Cursor globally",
    )
    setup_p.add_argument("--master-key", help="Master ACTA_API_KEY (auto-mints per-GitHub-org keys in RAM)")
    setup_p.add_argument("--tenant-key", help="Single-client acta_tk_v1 key (for external client machines)")
    setup_p.add_argument("--default-tenant", default="ardyn-intelligence", help="Fallback tenant outside Git repos")
    setup_p.add_argument("--url", default=DEFAULT_CLOUDRUN_URL, help="Acta Cloud Run URL")
    setup_p.add_argument("--host-pubkey", default=DEFAULT_LIVE_HOST_PUBKEY, help="Pinned Ed25519 host verifying key")

    sub.add_parser("status", help="Show which tenant_id & scope the current Git directory maps to")
    sub.add_parser("serve", help="Run stdio JSON-RPC 2.0 MCP bridge for the current directory")
    sub.add_parser("mcp-serve", help="Alias for serve")

    mint_p = sub.add_parser("mint-key", help="Mint a stateless acta_tk_v1 key for an external client")
    mint_p.add_argument("tenant_id", help="Business or client slug (e.g. client-acme)")
    mint_p.add_argument(
        "--master-key",
        default=os.environ.get("ACTA_MASTER_KEY") or os.environ.get("ACTA_API_KEY"),
        help="Master ACTA_API_KEY secret (defaults to ~/.config/acta/credentials.json if saved)",
    )
    mint_p.add_argument("--url", default=os.environ.get("ACTA_BASE_URL", DEFAULT_CLOUDRUN_URL))

    args = parser.parse_args(argv)

    if args.cmd == "setup":
        master = args.master_key or os.environ.get("ACTA_MASTER_KEY")
        tkey = args.tenant_key or os.environ.get("ACTA_API_KEY")
        if not master and not tkey:
            print("Error: pass --master-key <MASTER_SECRET> or --tenant-key <acta_tk_v1:...>", file=sys.stderr)
            return 2
        cred_file = save_credentials(
            base_url=args.url,
            master_key=master,
            tenant_key=tkey if not master else None,
            default_tenant=args.default_tenant,
            pinned_host_public_key=args.host_pubkey,
        )
        updated_files = install_global_mcp_configs()
        print(f"[acta-mcp] Saved 0600 credentials to {cred_file}")
        for fp in updated_files:
            print(f"[acta-mcp] Registered global MCP bridge in {fp}")
        print("[acta-mcp] Done! Every cloned GitHub repo now routes org -> tenant_id and repo -> scope automatically.")
        return 0

    if args.cmd == "status":
        creds = load_credentials()
        routing = resolve_git_workspace_context(
            fallback_tenant=str(creds.get("default_tenant") or "ardyn-intelligence")
        )
        print(
            json.dumps(
                {
                    "tenant_id": routing.tenant_id,
                    "default_scope": routing.default_scope,
                    "routing_source": routing.source,
                    "git_remote": routing.git_remote,
                    "cwd": routing.cwd,
                    "base_url": creds.get("base_url", DEFAULT_CLOUDRUN_URL),
                },
                indent=2,
            )
        )
        return 0

    if args.cmd in ("serve", "mcp-serve"):
        bridge = ActaGitMcpBridge()
        try:
            bridge.serve_stdio()
        finally:
            bridge.close()
        return 0

    if args.cmd == "mint-key":
        creds = load_credentials()
        master = args.master_key or creds.get("master_key")
        if not master:
            print("Error: pass --master-key or run `acta-mcp setup --master-key ...` first", file=sys.stderr)
            return 2
        token = mint_tenant_api_key(str(master), args.tenant_id)
        print(token)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
