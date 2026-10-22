#!/usr/bin/env python3
"""Check a release binary's stdio MCP handshake without upstream traffic."""

import json
import os
import subprocess
import sys
import tempfile


def request(method, request_id=None, params=None):
    message = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        message["id"] = request_id
    if params is not None:
        message["params"] = params
    return json.dumps(message) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: smoke.py <binary>")
    messages = (
        request("initialize", 1, {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "release-smoke", "version": "1"}})
        + request("notifications/initialized")
        + request("tools/list", 2, {})
    )
    env = os.environ.copy()
    env.pop("NVD_API", None)
    with tempfile.TemporaryDirectory() as directory:
        result = subprocess.run([os.path.abspath(sys.argv[1])], input=messages, text=True, capture_output=True, cwd=directory, env=env, timeout=15, check=False)
    if result.returncode != 0:
        sys.exit(f"MCP server exited {result.returncode}: {result.stderr[-500:]}")
    responses = {message["id"]: message for line in result.stdout.splitlines() if (message := json.loads(line)).get("id") in (1, 2)}
    if "serverInfo" not in responses.get(1, {}).get("result", {}):
        sys.exit("MCP initialize failed")
    names = {tool["name"] for tool in responses.get(2, {}).get("result", {}).get("tools", [])}
    expected = {"nvd_cve", "epss_scores", "kev_lookup", "enrich_cve", "product_cves", "scan_sbom", "poc_search"}
    if names != expected:
        sys.exit(f"MCP tools/list mismatch: {sorted(names)}")
    print("MCP initialize and tools/list passed")
