use std::collections::HashSet;
use std::process::Stdio;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::component::Component;
use crate::lockfile;

const IMAGE_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_IMAGE_SBOM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMAGE_STDERR_BYTES: u64 = 64 * 1024;

pub struct Sbom {
    pub format: &'static str,
    pub components: Vec<Component>,
}

/// Reads a lockfile chosen by `file_name`, or else an SBOM document. Duplicate components are
/// dropped.
pub fn parse_file(file_name: &str, bytes: &[u8]) -> Result<Sbom, String> {
    match lockfile::parse(file_name, bytes) {
        Some(parsed) => {
            let (format, components) = parsed?;
            Ok(Sbom {
                format,
                components: dedupe(components),
            })
        }
        None => parse(bytes),
    }
}

/// Whether `file_name` is a supported lockfile or follows a usual SBOM naming.
pub fn is_inventory(file_name: &str) -> bool {
    let lower = file_name.to_ascii_lowercase();
    // A supported lockfile name returns Some even for empty input.
    lockfile::parse(file_name, b"").is_some()
        || matches!(lower.as_str(), "bom.json" | "sbom.json")
        || [
            ".cdx.json",
            ".bom.json",
            ".sbom.json",
            ".spdx.json",
            ".spdx",
        ]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

/// Generates a CycloneDX SBOM for a container image with Trivy, or with Syft when Trivy is not
/// installed. GUI-launched clients often omit Homebrew from PATH, so its usual paths are tried too.
pub async fn from_image(image: &str) -> Result<(&'static str, Vec<u8>), String> {
    let valid = !image.is_empty()
        && image.len() <= 255
        && !image.starts_with('-')
        && image
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/:@-".contains(&b));
    if !valid {
        return Err(format!("{image:?} is not a valid image reference"));
    }
    let tools: [(&'static str, Vec<&str>); 2] = [
        (
            "trivy",
            vec!["image", "--quiet", "--format", "cyclonedx", image],
        ),
        ("syft", vec![image, "--quiet", "-o", "cyclonedx-json"]),
    ];
    for (tool, args) in tools {
        for program in [
            tool.to_string(),
            format!("/opt/homebrew/bin/{tool}"),
            format!("/usr/local/bin/{tool}"),
        ] {
            let child = tokio::process::Command::new(&program)
                .args(&args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn();
            let mut child = match child {
                Ok(child) => child,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("{tool}: {e}")),
            };
            let stdout = child.stdout.take().expect("stdout is piped");
            let stderr = child.stderr.take().expect("stderr is piped");
            let (stdout, stderr, status) = tokio::time::timeout(IMAGE_TIMEOUT, async {
                tokio::try_join!(
                    read_limited(stdout, MAX_IMAGE_SBOM_BYTES, tool, "stdout"),
                    read_limited(stderr, MAX_IMAGE_STDERR_BYTES, tool, "stderr"),
                    async { child.wait().await.map_err(|e| format!("{tool}: {e}")) },
                )
            })
                .await
                .map_err(|_| {
                    format!(
                        "{tool} took longer than {} s to read {image}; run `trivy image --format cyclonedx --output sbom.json {image}` and scan the file instead",
                        IMAGE_TIMEOUT.as_secs()
                    )
                })??;
            if !status.success() {
                let stderr = String::from_utf8_lossy(&stderr);
                let last: String = stderr
                    .trim()
                    .lines()
                    .last()
                    .unwrap_or_default()
                    .chars()
                    .take(300)
                    .collect();
                return Err(format!("{tool} could not read {image}: {last}"));
            }
            return Ok((tool, stdout));
        }
    }
    Err("scanning an image needs Trivy or Syft installed".to_string())
}

async fn read_limited<R: AsyncRead + Unpin>(
    reader: R,
    limit: u64,
    tool: &str,
    stream: &str,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| format!("{tool} {stream}: {e}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{tool} {stream} exceeded {limit} bytes"));
    }
    Ok(bytes)
}

/// Reads a CycloneDX JSON, SPDX JSON or SPDX tag-value document. Duplicate components are
/// dropped.
pub fn parse(bytes: &[u8]) -> Result<Sbom, String> {
    let (format, components) = match serde_json::from_slice::<Value>(bytes) {
        Ok(doc) if doc.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") => {
            let mut out = Vec::new();
            cyclonedx(&doc, &mut out);
            ("cyclonedx-json", out)
        }
        Ok(doc) if doc.get("spdxVersion").is_some() => ("spdx-json", spdx_json(&doc)),
        Ok(_) => return Err("JSON document is neither CycloneDX nor SPDX".to_string()),
        Err(_) => {
            let text = std::str::from_utf8(bytes).map_err(|_| "SBOM is not UTF-8 text")?;
            if !text
                .lines()
                .any(|l| l.trim_start().starts_with("SPDXVersion:"))
            {
                return Err(
                    "unsupported SBOM format: expected CycloneDX JSON or SPDX JSON or tag-value"
                        .to_string(),
                );
            }
            ("spdx-tag-value", spdx_tag_value(text))
        }
    };
    Ok(Sbom {
        format,
        components: dedupe(components),
    })
}

fn dedupe(components: Vec<Component>) -> Vec<Component> {
    let mut seen = HashSet::new();
    components
        .into_iter()
        .filter(|c| seen.insert(c.clone()))
        .collect()
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn component(
    name: Option<String>,
    version: Option<String>,
    purl: Option<String>,
    cpe: Option<String>,
) -> Option<Component> {
    let name = name.unwrap_or_default();
    (!name.is_empty() || purl.is_some() || cpe.is_some()).then_some(Component {
        name,
        version,
        purl,
        cpe,
        ecosystem: None,
    })
}

fn cyclonedx(node: &Value, out: &mut Vec<Component>) {
    for c in node
        .get("components")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        // The image's OS entry is not a package; its packages are listed individually.
        if text(c, "type").as_deref() == Some("operating-system") {
            continue;
        }
        out.extend(component(
            text(c, "name"),
            text(c, "version"),
            with_trivy_source(text(c, "purl"), c),
            text(c, "cpe"),
        ));
        cyclonedx(c, out);
    }
}

/// Trivy records a Debian, Ubuntu or Alpine package's source package as a property rather than
/// the `upstream` qualifier, and OSV indexes those distributions by source package.
fn with_trivy_source(purl: Option<String>, c: &Value) -> Option<String> {
    let purl = purl?;
    let os_package = purl.starts_with("pkg:deb/") || purl.starts_with("pkg:apk/");
    if !os_package || purl.contains("upstream=") {
        return Some(purl);
    }
    let source = c
        .get("properties")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|p| text(p, "name").as_deref() == Some("aquasecurity:trivy:SrcName"))
        .and_then(|p| text(p, "value"))
        .filter(|s| {
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-._".contains(&b))
        });
    Some(match source {
        Some(source) => {
            let sep = if purl.contains('?') { '&' } else { '?' };
            format!("{purl}{sep}upstream={}", source.replace('+', "%2B"))
        }
        None => purl,
    })
}

fn spdx_json(doc: &Value) -> Vec<Component> {
    let packages = doc
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    packages
        .filter_map(|p| {
            let refs = p.get("externalRefs").and_then(Value::as_array);
            let locator = |kind: &str| {
                refs.into_iter()
                    .flatten()
                    .find(|r| text(r, "referenceType").as_deref() == Some(kind))
                    .and_then(|r| text(r, "referenceLocator"))
            };
            component(
                text(p, "name"),
                text(p, "versionInfo"),
                locator("purl"),
                locator("cpe23Type"),
            )
        })
        .collect()
}

fn spdx_tag_value(text: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut current: Option<Component> = None;
    for line in text.lines() {
        let Some((tag, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_string();
        match tag.trim() {
            "PackageName" => {
                out.extend(current.take());
                current = component(Some(value), None, None, None);
            }
            "PackageVersion" => {
                if let Some(c) = current.as_mut() {
                    c.version = Some(value).filter(|v| !v.is_empty());
                }
            }
            "ExternalRef" => {
                let mut parts = value.split_whitespace();
                let (_, kind, locator) = (parts.next(), parts.next(), parts.next());
                if let (Some(c), Some(locator)) = (current.as_mut(), locator) {
                    match kind {
                        Some("purl") => c.purl = Some(locator.to_string()),
                        Some("cpe23Type") => c.cpe = Some(locator.to_string()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    out.extend(current);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn image_output_limit_accepts_exact_size_and_rejects_overflow() {
        for (limit, expected_error) in [(5, false), (4, true)] {
            let (mut writer, reader) = tokio::io::duplex(16);
            tokio::spawn(async move {
                writer.write_all(b"12345").await.unwrap();
            });
            let result = read_limited(reader, limit, "trivy", "stdout").await;
            if expected_error {
                assert!(result.unwrap_err().contains("stdout exceeded"));
            } else {
                assert_eq!(result.unwrap(), b"12345");
            }
        }
    }

    #[tokio::test]
    async fn image_error_output_is_bounded() {
        let (mut writer, reader) = tokio::io::duplex(16);
        tokio::spawn(async move {
            writer.write_all(b"12345").await.unwrap();
        });
        assert!(
            read_limited(reader, 4, "syft", "stderr")
                .await
                .unwrap_err()
                .contains("stderr exceeded")
        );
    }

    #[test]
    fn cyclonedx_reads_nested_components_and_drops_duplicates() {
        let doc = br#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
            {"type":"library","name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
             "components":[{"name":"nginx","version":"1.18.0","cpe":"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}]},
            {"type":"library","name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
            {"type":"operating-system","name":"ubuntu","version":"20.04"}]}"#;
        let sbom = parse(doc).unwrap();
        assert_eq!(sbom.format, "cyclonedx-json");
        assert_eq!(
            sbom.components.len(),
            2,
            "duplicate and OS entries are dropped"
        );
        assert_eq!(
            sbom.components[1].cpe.as_deref(),
            Some("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*")
        );
    }

    #[test]
    fn spdx_json_reads_purl_and_cpe_refs() {
        let doc = br#"{"spdxVersion":"SPDX-2.3","packages":[
            {"name":"openssl","versionInfo":"1.1.1n-0+deb11u3","externalRefs":[
                {"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:openssl:openssl:1.1.1n:*:*:*:*:*:*:*"},
                {"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:deb/debian/openssl@1.1.1n-0+deb11u3?distro=debian-11"}]},
            {"name":"scanned-dir"}]}"#;
        let sbom = parse(doc).unwrap();
        assert_eq!(sbom.format, "spdx-json");
        assert_eq!(sbom.components.len(), 2);
        let c = &sbom.components[0];
        assert_eq!(c.version.as_deref(), Some("1.1.1n-0+deb11u3"));
        assert!(
            c.purl
                .as_deref()
                .unwrap()
                .starts_with("pkg:deb/debian/openssl")
        );
        assert!(c.cpe.is_some());
        assert_eq!(sbom.components[1].version, None);
    }

    #[test]
    fn trivy_source_package_becomes_the_upstream_qualifier() {
        let doc = br#"{"bomFormat":"CycloneDX","components":[
            {"name":"libssl1.1","version":"1.1.1w-0+deb11u8","purl":"pkg:deb/debian/libssl1.1@1.1.1w-0%2Bdeb11u8?arch=amd64&distro=debian-11.11",
             "properties":[{"name":"aquasecurity:trivy:SrcName","value":"openssl"}]},
            {"name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20",
             "properties":[{"name":"aquasecurity:trivy:SrcName","value":"ignored"}]}]}"#;
        let sbom = parse(doc).unwrap();
        assert_eq!(
            sbom.components[0].purl.as_deref(),
            Some(
                "pkg:deb/debian/libssl1.1@1.1.1w-0%2Bdeb11u8?arch=amd64&distro=debian-11.11&upstream=openssl"
            )
        );
        assert_eq!(
            sbom.components[1].purl.as_deref(),
            Some("pkg:npm/lodash@4.17.20")
        );
    }

    #[test]
    fn spdx_tag_value_reads_packages() {
        let doc = b"SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\n\nPackageName: lodash\nPackageVersion: 4.17.20\nExternalRef: PACKAGE-MANAGER purl pkg:npm/lodash@4.17.20\n\nPackageName: nginx\nPackageVersion: 1.18.0\nExternalRef: SECURITY cpe23Type cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*\n";
        let sbom = parse(doc).unwrap();
        assert_eq!(sbom.format, "spdx-tag-value");
        assert_eq!(sbom.components.len(), 2);
        assert_eq!(
            sbom.components[0].purl.as_deref(),
            Some("pkg:npm/lodash@4.17.20")
        );
        assert_eq!(sbom.components[1].version.as_deref(), Some("1.18.0"));
    }

    #[test]
    fn inventory_names_are_lockfiles_and_sbom_conventions() {
        for name in [
            "Cargo.lock",
            "requirements-dev.txt",
            "bom.json",
            "app.cdx.json",
            "image.spdx",
        ] {
            assert!(is_inventory(name), "{name}");
        }
        for name in [
            "package.json",
            "bom.json.oxiploitability.json",
            ".env",
            "notes.txt",
        ] {
            assert!(!is_inventory(name), "{name}");
        }
    }

    #[test]
    fn other_documents_are_rejected() {
        assert!(parse(br#"{"name":"package.json"}"#).is_err());
        assert!(parse(b"just some notes").is_err());
        assert!(parse(&[0xff, 0xfe, 0x00]).is_err());
    }
}
