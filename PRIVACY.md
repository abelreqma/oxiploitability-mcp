# Privacy

Oxiploitability runs as a local stdio MCP server. It does not use an account or send telemetry. The server makes outbound requests when a client calls a research tool. Those providers can log requests under their own privacy policies.

The server sends CVE IDs to NIST NVD, FIRST EPSS, CVE.org and the public PoC index on GitHub as needed. It downloads the CISA KEV catalog. Product searches send product names, versions or CPEs to NVD. Package and SBOM checks send component names, versions and package URLs to OSV.dev, and may send CPEs or CVE IDs to NVD and CVE.org. The server does not upload the full SBOM or lockfile. Container image scans run an installed Trivy or Syft executable, which may pull the named image from its registry under that tool's own configuration.

An optional NVD API key is read from `NVD_API` in the process environment or from a `.env` file in the working directory. It is sent only to NVD as an API key header. Do not put the key in a command line, a checked-in configuration file or a bug report.

Research responses are cached in process memory and discarded when the process exits. `scan_sbom` writes a new JSON report beside the input file, in the scanned directory, or in the temporary directory for an image; it does not replace an existing report. The other tools do not write reports. The server logs to stderr, and debug logging can include request details. The MCP client and operating system may retain their own logs and configuration.

Provider policies: [NIST](https://www.nist.gov/admr/oism/site-privacy), [FIRST](https://www.first.org/about/policies/privacy), [CISA](https://www.cisa.gov/privacy-policy), [Google for OSV.dev](https://policies.google.com/privacy), [CVE.org](https://www.cve.org/legal/privacypolicy), and [GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).
