# oxiploitability-mcp

Oxiploitability is a Rust MCP server for sourced CVE research. It combines NVD vulnerability records, FIRST EPSS probabilities, CISA KEV entries, OSV package advisories, CVE.org records and a public proof-of-concept index. It can also check supported SBOMs, lockfiles, project directories and container images.

This product uses the NVD API but is not endorsed or certified by NVD. EPSS is published by FIRST, KEV by CISA, package advisories by OSV.dev, CVE records by CVE.org and public proof-of-concept links by the nomi-sec/PoC-in-GitHub index.

mcp-name: io.github.abelreqma/oxiploitability-mcp

## Tools

| Tool | Input | Result |
|---|---|---|
| `enrich_cve` | One CVE or up to 100 CVEs | Combined NVD, EPSS, KEV, CVE.org and PoC data with source errors kept separate. |
| `nvd_cve` | One CVE | NVD description, scores, weaknesses, affected products and references. |
| `epss_scores` | Up to 100 CVEs | EPSS probabilities and percentiles. |
| `kev_lookup` | Up to 100 CVEs | CISA KEV entries and unlisted IDs. |
| `product_cves` | Product name, CPE, package URL or package name | Ranked CVEs, version evidence and a suggested action. |
| `scan_sbom` | SBOM, lockfile, directory or image | Component findings, unchecked items, actions and a new local JSON report. |
| `poc_search` | One CVE | Public repository links from the PoC index; these are unvetted leads. |

Findings name their source and link to its record. `nvd-cpe`, `cve.org-cna` and `osv:*` identify product or package evidence; `nvd-description` is a lead with `confirmed: false`. A missing score, KEV entry or PoC is not evidence that a vulnerability is safe or unexploited. Check `partial`, `warnings`, `needs_verification` and `not_checked` before relying on an answer.

Lookup tools do not write local files. `scan_sbom` creates a new report without replacing an existing one; an image scan may pull the image through Trivy or Syft if installed. See [PRIVACY.md](PRIVACY.md) for outbound data and local files.

## Install from a checkout

From this repository, install the native executable with:

```bash
cargo install --path . --locked
```

The executable is normally `~/.cargo/bin/oxiploitability`. Rust builds native executables for each operating system and CPU architecture, so use a matching build and its full path in desktop client settings; desktop apps may not inherit your shell's `PATH`.

An NVD API key is optional. Set `NVD_API` in the private environment of a CLI client if you have one; do not commit a key to this repository. Without a key, the server uses NVD's lower request limit.

## Configure a client

### Claude Desktop on macOS

Add this entry to `mcpServers` in `~/Library/Application Support/Claude/claude_desktop_config.json`, preserving other servers, and restart Claude Desktop when convenient:

```json
{
  "mcpServers": {
    "oxiploitability": {
      "command": "/absolute/path/to/oxiploitability",
      "args": []
    }
  }
}
```

The optional NVD key field in the packaged MCPB extension has a [known Claude Desktop delivery issue](https://github.com/modelcontextprotocol/mcpb/issues/297) for some binary servers. A keyless setup works without it. Release bundles can also be installed as platform-specific `.mcpb` files through Settings > Extensions > Advanced settings > Install Extension.

### Claude Code

```bash
claude mcp add --transport stdio --scope user oxiploitability -- /absolute/path/to/oxiploitability
```

### Codex CLI

```bash
codex mcp add oxiploitability -- /absolute/path/to/oxiploitability
```

Start a fresh Codex chat after adding the server. If you edit `~/.codex/config.toml` instead, use `[mcp_servers.oxiploitability]` with `command = "/absolute/path/to/oxiploitability"`.

### Hermes Agent

Merge this entry under `mcp_servers` in `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  oxiploitability:
    command: /absolute/path/to/oxiploitability
```

Run `hermes mcp test oxiploitability` to check discovery. In an existing Hermes chat, use `/reload-mcp` after changing the config.

## Development and release

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
python3 -m unittest discover -s mcpb -p 'test_*.py'
```

Tests use local mock HTTP responses. CI builds the macOS, Linux and Windows bundles before release. To publish, create a `v*` tag and manually run `gh workflow run release.yml --ref vX.Y.Z` for that tag; the workflow verifies the staged assets before publishing to crates.io and the MCP Registry. Do not run it until the client installations have been checked.

## License

Licensed under MIT or Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).
