use std::str::FromStr;

use packageurl::PackageUrl;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::nvd::cpe_fields;

const OSV_PURL_TYPES: [&str; 14] = [
    "npm", "pypi", "maven", "golang", "cargo", "gem", "nuget", "composer", "hex", "pub", "swift",
    "cran", "hackage", "rpm",
];
const ECOSYSTEMS: [&str; 13] = [
    "npm",
    "PyPI",
    "Maven",
    "Go",
    "crates.io",
    "RubyGems",
    "NuGet",
    "Packagist",
    "Hex",
    "Pub",
    "SwiftURL",
    "CRAN",
    "Hackage",
];
const ECOSYSTEM_PREFIXES: [&str; 6] = [
    "Debian:",
    "Alpine:",
    "Ubuntu:",
    "Red Hat",
    "Rocky Linux",
    "AlmaLinux",
];
const DEBIAN_CODENAMES: [(&str, &str); 4] = [
    ("buster", "10"),
    ("bullseye", "11"),
    ("bookworm", "12"),
    ("trixie", "13"),
];

/// One software component to check, as supplied by the caller or read from an inventory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Component {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
    pub ecosystem: Option<String>,
}

/// A query for the OSV querybatch endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct OsvQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl OsvQuery {
    pub fn to_json(&self) -> Value {
        let package = match &self.purl {
            Some(purl) => json!({ "purl": purl }),
            None => json!({ "name": self.name, "ecosystem": self.ecosystem }),
        };
        match &self.version {
            Some(version) => json!({ "package": package, "version": version }),
            None => json!({ "package": package }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NvdTarget {
    Cpe {
        part: String,
        vendor: String,
        product: String,
    },
    Name(String),
}

#[derive(Debug, Clone)]
pub enum Route {
    Osv(OsvQuery),
    Nvd {
        target: NvdTarget,
        version: Option<String>,
    },
    NotChecked(NotCheckedReason),
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotCheckedReason {
    NoVersion,
    AmbiguousName {
        candidates: Vec<String>,
    },
    UnknownName,
    OsPackageWithoutDistro,
    InvalidPurl,
    Upstream {
        error: String,
    },
    /// Not checked because the scan's NVD time limit ran out; product_cves can check it alone.
    NvdBudget,
    /// Not checked because the scan's OSV time limit ran out.
    TimeBudget,
    /// Not checked because the scan reached its limit on queued components.
    ComponentLimit,
}

/// Chooses the vulnerability source for a component: a supported purl, then a named ecosystem,
/// then a CPE, then the bare name.
pub fn route(c: &Component, require_version: bool) -> Route {
    let mut version = non_empty(&c.version);
    let mut name = c.name.clone();
    let missing_version = |v: &Option<String>| require_version && v.is_none();

    if let Some(raw) = non_empty(&c.purl) {
        let Ok(purl) = PackageUrl::from_str(&raw) else {
            return Route::NotChecked(NotCheckedReason::InvalidPurl);
        };
        let purl_version = purl.version().map(str::to_string);
        let effective = purl_version.clone().or_else(|| version.clone());
        match purl.ty() {
            "deb" | "apk" => {
                let distro = purl.qualifiers().get("distro").map(|d| d.to_lowercase());
                if purl.ty() == "deb" && distro.as_deref().is_some_and(|d| d.starts_with("ubuntu-"))
                {
                    if missing_version(&effective) {
                        return Route::NotChecked(NotCheckedReason::NoVersion);
                    }
                    let purl = match source_name(&purl) {
                        Some(source) => with_source_name(&purl, source),
                        None => purl,
                    };
                    return Route::Osv(purl_query(&purl, purl_version, version));
                }
                let ecosystem = distro.as_deref().and_then(|d| match purl.ty() {
                    "deb" => debian_ecosystem(d),
                    _ => alpine_ecosystem(d),
                });
                let Some(ecosystem) = ecosystem else {
                    return Route::NotChecked(NotCheckedReason::OsPackageWithoutDistro);
                };
                if missing_version(&effective) {
                    return Route::NotChecked(NotCheckedReason::NoVersion);
                }
                let source = source_name(&purl).unwrap_or(purl.name());
                return Route::Osv(OsvQuery {
                    purl: None,
                    name: Some(source.to_string()),
                    ecosystem: Some(ecosystem),
                    version: effective,
                });
            }
            ty if OSV_PURL_TYPES.contains(&ty) => {
                if missing_version(&effective) {
                    return Route::NotChecked(NotCheckedReason::NoVersion);
                }
                return Route::Osv(purl_query(&purl, purl_version, version));
            }
            _ => {
                version = effective;
                if name.trim().is_empty() {
                    name = purl.name().to_string();
                }
            }
        }
    }

    if let Some(ecosystem) = non_empty(&c.ecosystem).and_then(|e| canonical_ecosystem(&e)) {
        if missing_version(&version) {
            return Route::NotChecked(NotCheckedReason::NoVersion);
        }
        return Route::Osv(OsvQuery {
            purl: None,
            name: Some(name),
            ecosystem: Some(ecosystem),
            version,
        });
    }

    let mut target = NvdTarget::Name(name);
    if let Some(raw) = non_empty(&c.cpe) {
        let fields = cpe_fields(&raw);
        let field = |i: usize| {
            fields
                .get(i)
                .copied()
                .filter(|f| !f.is_empty() && *f != "*")
        };
        let is_cpe23 = fields.first() == Some(&"cpe") && fields.get(1) == Some(&"2.3");
        if let (true, Some(part @ ("a" | "o" | "h")), Some(vendor), Some(product)) =
            (is_cpe23, field(2), field(3), field(4))
        {
            target = NvdTarget::Cpe {
                part: part.to_string(),
                vendor: vendor.to_string(),
                product: product.to_string(),
            };
            if version.is_none() {
                version = field(5).filter(|v| *v != "-").map(str::to_string);
            }
        }
    }
    if missing_version(&version) {
        return Route::NotChecked(NotCheckedReason::NoVersion);
    }
    Route::Nvd { target, version }
}

fn non_empty(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// The source package named by the `upstream` qualifier, without its `@version` suffix.
fn source_name<'a>(purl: &'a PackageUrl<'_>) -> Option<&'a str> {
    purl.qualifiers()
        .get("upstream")
        .and_then(|u| u.split('@').next())
        .filter(|u| !u.is_empty())
}

/// Copy of `purl` that names `source` and drops the `upstream` qualifier.
fn with_source_name(purl: &PackageUrl<'_>, source: &str) -> PackageUrl<'static> {
    let mut renamed = PackageUrl::new(purl.ty().to_string(), source.to_string())
        .expect("type and non-empty name come from a parsed purl");
    if let Some(ns) = purl.namespace() {
        renamed.with_namespace(ns.to_string()).ok();
    }
    if let Some(v) = purl.version() {
        renamed.with_version(v.to_string()).ok();
    }
    for (k, v) in purl.qualifiers().iter().filter(|(k, _)| *k != "upstream") {
        renamed.add_qualifier(k.to_string(), v.to_string()).ok();
    }
    renamed
}

/// Rebuilds the purl with a decoded version. OSV rejects a version both in the purl and beside it,
/// so a separate version is sent only when the purl carries none.
fn purl_query(
    purl: &PackageUrl<'_>,
    purl_version: Option<String>,
    version: Option<String>,
) -> OsvQuery {
    let mut bare = purl.clone();
    bare.without_version().without_subpath();
    let mut text = bare.to_string();
    let separate = match purl_version {
        Some(v) => {
            let at = text.find('?').unwrap_or(text.len());
            let v = v
                .replace('%', "%25")
                .replace('?', "%3F")
                .replace('#', "%23");
            text.insert_str(at, &format!("@{v}"));
            None
        }
        None => version,
    };
    OsvQuery {
        purl: Some(text),
        name: None,
        ecosystem: None,
        version: separate,
    }
}

fn debian_ecosystem(distro: &str) -> Option<String> {
    let release = distro.strip_prefix("debian-").unwrap_or(distro);
    if let Some((_, number)) = DEBIAN_CODENAMES.iter().find(|(name, _)| *name == release) {
        return Some(format!("Debian:{number}"));
    }
    let major = release.split('.').next()?;
    (!major.is_empty() && major.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("Debian:{major}"))
}

/// Accepts `alpine-3.14.2` (Syft) and a bare `3.14.10` (Trivy).
fn alpine_ecosystem(distro: &str) -> Option<String> {
    let release = distro.strip_prefix("alpine-").unwrap_or(distro);
    let mut parts = release.split('.');
    let (major, minor) = (parts.next()?, parts.next()?);
    let numeric = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    (numeric(major) && numeric(minor)).then(|| format!("Alpine:v{major}.{minor}"))
}

fn canonical_ecosystem(raw: &str) -> Option<String> {
    if ECOSYSTEM_PREFIXES.iter().any(|p| raw.starts_with(p)) {
        return Some(raw.to_string());
    }
    ECOSYSTEMS
        .iter()
        .find(|e| e.eq_ignore_ascii_case(raw))
        .map(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(
        name: &str,
        version: Option<&str>,
        purl: Option<&str>,
        cpe: Option<&str>,
        eco: Option<&str>,
    ) -> Component {
        let own = |s: Option<&str>| s.map(str::to_string);
        Component {
            name: name.to_string(),
            version: own(version),
            purl: own(purl),
            cpe: own(cpe),
            ecosystem: own(eco),
        }
    }

    fn r_osv(route: Route) -> OsvQuery {
        match route {
            Route::Osv(q) => q,
            other => panic!("expected an OSV route, got {other:?}"),
        }
    }

    #[test]
    fn supported_purl_routes_to_osv_as_given() {
        let r = route(
            &c("lodash", None, Some("pkg:npm/lodash@4.17.20"), None, None),
            true,
        );
        assert!(
            matches!(r, Route::Osv(OsvQuery { purl: Some(ref p), .. }) if p == "pkg:npm/lodash@4.17.20")
        );
    }

    #[test]
    fn unsupported_purl_type_falls_back_to_cpe_then_name() {
        let r = route(
            &c(
                "nginx",
                Some("1.18.0"),
                Some("pkg:generic/nginx@1.18.0"),
                None,
                None,
            ),
            true,
        );
        assert!(
            matches!(r, Route::Nvd { target: NvdTarget::Name(ref n), version: Some(ref v) } if n == "nginx" && v == "1.18.0")
        );
        let r = route(
            &c(
                "nginx",
                Some("1.18.0"),
                Some("pkg:docker/nginx@1.18.0"),
                Some("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"),
                None,
            ),
            true,
        );
        assert!(
            matches!(r, Route::Nvd { target: NvdTarget::Cpe { ref vendor, ref product, .. }, .. } if vendor == "f5" && product == "nginx")
        );
    }

    #[test]
    fn debian_and_alpine_purls_convert_to_ecosystem_queries() {
        let r = route(
            &c(
                "openssl",
                None,
                Some("pkg:deb/debian/openssl@1.1.1n-0%2Bdeb11u3?arch=amd64&distro=debian-11"),
                None,
                None,
            ),
            true,
        );
        assert_eq!(
            r_osv(r),
            OsvQuery {
                purl: None,
                name: Some("openssl".into()),
                ecosystem: Some("Debian:11".into()),
                version: Some("1.1.1n-0+deb11u3".into())
            }
        );
        let r = route(
            &c(
                "openssl",
                None,
                Some("pkg:apk/alpine/openssl@1.1.1k-r0?distro=alpine-3.14.2"),
                None,
                None,
            ),
            true,
        );
        assert_eq!(r_osv(r).ecosystem.as_deref(), Some("Alpine:v3.14"));
        let r = route(
            &c(
                "openssl",
                None,
                Some("pkg:deb/debian/openssl@1.1.1n-0+deb11u3"),
                None,
                None,
            ),
            true,
        );
        assert!(matches!(
            r,
            Route::NotChecked(NotCheckedReason::OsPackageWithoutDistro)
        ));
    }

    #[test]
    fn debian_codename_distro_maps_to_release_number() {
        let r = route(
            &c(
                "openssl",
                None,
                Some("pkg:deb/debian/openssl@3.0.11-1?distro=bookworm"),
                None,
                None,
            ),
            true,
        );
        assert_eq!(r_osv(r).ecosystem.as_deref(), Some("Debian:12"));
    }

    #[test]
    fn ubuntu_deb_purl_stays_a_purl_with_decoded_version() {
        let r = route(
            &c(
                "openssl",
                None,
                Some(
                    "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2%2Besm1?arch=amd64&distro=ubuntu-20.04",
                ),
                None,
                None,
            ),
            true,
        );
        let q = r_osv(r);
        assert_eq!(
            q.purl.as_deref(),
            Some("pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2+esm1?arch=amd64&distro=ubuntu-20.04")
        );
        assert_eq!((q.name, q.ecosystem, q.version), (None, None, None));
    }

    #[test]
    fn ubuntu_upstream_qualifier_renames_the_purl_to_the_source_package() {
        let raw = "pkg:deb/ubuntu/libssl1.1@1.1.1f-1ubuntu2?distro=ubuntu-20.04&upstream=openssl";
        let q = r_osv(route(&c("libssl1.1", None, Some(raw), None, None), true));
        assert_eq!(
            q.purl.as_deref(),
            Some("pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2?distro=ubuntu-20.04")
        );
        let raw = "pkg:deb/ubuntu/libssl1.1@1.1.1f-1ubuntu2?distro=ubuntu-20.04&upstream=openssl%401.1.1f-1ubuntu2";
        let q = r_osv(route(&c("libssl1.1", None, Some(raw), None, None), true));
        assert_eq!(
            q.purl.as_deref(),
            Some("pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2?distro=ubuntu-20.04")
        );
    }

    #[test]
    fn percent_encoded_purl_version_is_decoded() {
        let r = route(
            &c("x", None, Some("pkg:pypi/foo@1.0%2Blocal"), None, None),
            true,
        );
        assert_eq!(r_osv(r).purl.as_deref(), Some("pkg:pypi/foo@1.0+local"));
    }

    #[test]
    fn separate_version_is_sent_only_when_the_purl_has_none() {
        let r = route(
            &c(
                "lodash",
                Some("4.17.20"),
                Some("pkg:npm/lodash"),
                None,
                None,
            ),
            true,
        );
        let q = r_osv(r);
        assert_eq!(q.purl.as_deref(), Some("pkg:npm/lodash"));
        assert_eq!(q.version.as_deref(), Some("4.17.20"));
        let r = route(
            &c(
                "lodash",
                Some("1"),
                Some("pkg:npm/lodash@4.17.20"),
                None,
                None,
            ),
            true,
        );
        assert_eq!(r_osv(r).version, None);
    }

    #[test]
    fn name_with_known_ecosystem_routes_to_osv() {
        let r = route(
            &c("requests", Some("2.19.0"), None, None, Some("pypi")),
            true,
        );
        assert_eq!(
            r_osv(r),
            OsvQuery {
                purl: None,
                name: Some("requests".into()),
                ecosystem: Some("PyPI".into()),
                version: Some("2.19.0".into())
            }
        );
        let r = route(&c("curl", Some("7"), None, None, Some("Debian:12")), true);
        assert_eq!(r_osv(r).ecosystem.as_deref(), Some("Debian:12"));
    }

    #[test]
    fn unknown_ecosystem_falls_through_to_nvd() {
        let r = route(&c("nginx", Some("1.18.0"), None, None, Some("plan9")), true);
        assert!(matches!(
            r,
            Route::Nvd {
                target: NvdTarget::Name(_),
                ..
            }
        ));
    }

    #[test]
    fn trivy_alpine_distro_without_prefix_maps_to_the_release() {
        let purl = "pkg:apk/alpine/apk-tools@2.12.7-r0?arch=x86_64&distro=3.14.10";
        assert_eq!(
            r_osv(route(&c("apk-tools", None, Some(purl), None, None), true))
                .ecosystem
                .as_deref(),
            Some("Alpine:v3.14")
        );
    }

    #[test]
    fn missing_version_is_not_checked_only_when_required() {
        assert!(matches!(
            route(&c("nginx", None, None, None, None), true),
            Route::NotChecked(NotCheckedReason::NoVersion)
        ));
        assert!(matches!(
            route(&c("nginx", None, None, None, None), false),
            Route::Nvd { version: None, .. }
        ));
        assert!(matches!(
            route(&c("lodash", None, Some("pkg:npm/lodash"), None, None), true),
            Route::NotChecked(NotCheckedReason::NoVersion)
        ));
    }

    #[test]
    fn cpe_version_component_supplies_the_version() {
        let r = route(
            &c(
                "nginx",
                None,
                None,
                Some("cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"),
                None,
            ),
            true,
        );
        assert!(matches!(r, Route::Nvd { version: Some(ref v), .. } if v == "1.18.0"));
        let r = route(
            &c(
                "nginx",
                None,
                None,
                Some("cpe:2.3:a:f5:nginx:-:*:*:*:*:*:*:*"),
                None,
            ),
            true,
        );
        assert!(matches!(r, Route::NotChecked(NotCheckedReason::NoVersion)));
    }

    #[test]
    fn cpe_with_wildcard_vendor_falls_back_to_name() {
        let r = route(
            &c(
                "nginx",
                Some("1"),
                None,
                Some("cpe:2.3:a:*:nginx:*:*:*:*:*:*:*:*"),
                None,
            ),
            true,
        );
        assert!(matches!(
            r,
            Route::Nvd {
                target: NvdTarget::Name(_),
                ..
            }
        ));
    }

    #[test]
    fn unsupported_purl_supplies_version_and_name_to_nvd() {
        let r = route(
            &c("", None, Some("pkg:generic/nginx@1.18.0"), None, None),
            true,
        );
        assert!(
            matches!(r, Route::Nvd { target: NvdTarget::Name(ref n), version: Some(ref v) } if n == "nginx" && v == "1.18.0")
        );
        let r = route(
            &c(
                "nginx",
                None,
                Some("pkg:docker/nginx@1.18.0"),
                Some("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"),
                None,
            ),
            true,
        );
        assert!(matches!(r, Route::Nvd { version: Some(ref v), .. } if v == "1.18.0"));
    }

    #[test]
    fn cpe_22_uri_falls_back_to_name() {
        let r = route(
            &c(
                "nginx",
                Some("1.18.0"),
                None,
                Some("cpe:/a:f5:nginx:1.18.0"),
                None,
            ),
            true,
        );
        assert!(matches!(r, Route::Nvd { target: NvdTarget::Name(ref n), .. } if n == "nginx"));
    }

    #[test]
    fn cpe_with_unknown_part_falls_back_to_name() {
        let r = route(
            &c(
                "nginx",
                Some("1"),
                None,
                Some("cpe:2.3:x:f5:nginx:1:*:*:*:*:*:*:*"),
                None,
            ),
            true,
        );
        assert!(matches!(
            r,
            Route::Nvd {
                target: NvdTarget::Name(_),
                ..
            }
        ));
    }

    #[test]
    fn upstream_qualifier_selects_the_source_package_name() {
        let plain = "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u3?arch=amd64&upstream=openssl&distro=debian-11";
        let r = route(&c("libssl1.1", None, Some(plain), None, None), true);
        assert_eq!(
            r_osv(r),
            OsvQuery {
                purl: None,
                name: Some("openssl".into()),
                ecosystem: Some("Debian:11".into()),
                version: Some("1.1.1n-0+deb11u3".into())
            }
        );
        let versioned = "pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u3?arch=amd64&upstream=openssl%401.1.1n-0%2Bdeb11u3&distro=debian-11";
        let r = route(&c("libssl1.1", None, Some(versioned), None, None), true);
        assert_eq!(r_osv(r).name.as_deref(), Some("openssl"));
        let apk = "pkg:apk/alpine/libssl1.1@1.1.1k-r0?upstream=openssl&distro=alpine-3.14.2";
        let r = route(&c("libssl1.1", None, Some(apk), None, None), true);
        assert_eq!(r_osv(r).name.as_deref(), Some("openssl"));
        let none = "pkg:deb/debian/libssl1.1@1.1.1n-0?distro=debian-11";
        let r = route(&c("libssl1.1", None, Some(none), None, None), true);
        assert_eq!(r_osv(r).name.as_deref(), Some("libssl1.1"));
    }

    #[test]
    fn malformed_purl_is_reported() {
        assert!(matches!(
            route(&c("x", Some("1"), Some("pkg:"), None, None), true),
            Route::NotChecked(NotCheckedReason::InvalidPurl)
        ));
    }

    #[test]
    fn osv_query_serializes_to_the_osv_shape() {
        let by_name = OsvQuery {
            purl: None,
            name: Some("requests".into()),
            ecosystem: Some("PyPI".into()),
            version: Some("2.19.0".into()),
        };
        assert_eq!(
            by_name.to_json(),
            json!({"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"})
        );
        let by_purl = OsvQuery {
            purl: Some("pkg:npm/lodash@4.17.20".into()),
            name: None,
            ecosystem: None,
            version: None,
        };
        assert_eq!(
            by_purl.to_json(),
            json!({"package": {"purl": "pkg:npm/lodash@4.17.20"}})
        );
    }
}
