use serde_json::Value;

use crate::component::Component;

/// Parses a lockfile or manifest chosen by its file name. Returns `None` when the name is not a
/// supported lockfile, so the caller can try the SBOM formats instead.
pub fn parse(
    file_name: &str,
    bytes: &[u8],
) -> Option<Result<(&'static str, Vec<Component>), String>> {
    let text = || std::str::from_utf8(bytes).map_err(|_| format!("{file_name} is not UTF-8 text"));
    let json = || serde_json::from_slice::<Value>(bytes).map_err(|e| format!("{file_name}: {e}"));
    let lower = file_name.to_ascii_lowercase();
    let parsed = match lower.as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => json().map(|v| ("npm-lock", npm_lock(&v))),
        "yarn.lock" => text().map(|t| ("yarn-lock", yarn_lock(t))),
        "pnpm-lock.yaml" => text().map(|t| ("pnpm-lock", pnpm_lock(t))),
        "poetry.lock" => text().map(|t| ("poetry-lock", toml_packages(t, "PyPI", |_| true))),
        "uv.lock" => text().map(|t| {
            (
                "uv-lock",
                toml_packages(t, "PyPI", |s| s.contains("registry")),
            )
        }),
        "cargo.lock" => text().map(|t| {
            (
                "cargo-lock",
                toml_packages(t, "crates.io", |s| !s.is_empty()),
            )
        }),
        "pipfile.lock" => json().map(|v| ("pipfile-lock", pipfile_lock(&v))),
        "go.mod" => text().map(|t| ("go-mod", go_mod(t))),
        "gemfile.lock" => text().map(|t| ("gemfile-lock", gemfile_lock(t))),
        "composer.lock" => json().map(|v| ("composer-lock", composer_lock(&v))),
        "packages.lock.json" => json().map(|v| ("nuget-lock", nuget_lock(&v))),
        "gradle.lockfile" => text().map(|t| ("gradle-lockfile", gradle_lockfile(t))),
        name if name.starts_with("requirements") && name.ends_with(".txt") => {
            text().map(|t| ("requirements-txt", requirements(t)))
        }
        _ => return None,
    };
    Some(parsed)
}

fn package(name: &str, version: Option<&str>, ecosystem: &str) -> Component {
    Component {
        name: name.trim().to_string(),
        version: version
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        purl: None,
        cpe: None,
        ecosystem: Some(ecosystem.to_string()),
    }
}

/// npm lockfile v2 and v3 `packages`, falling back to the v1 `dependencies` tree.
fn npm_lock(doc: &Value) -> Vec<Component> {
    if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
        return packages
            .iter()
            .filter(|(path, p)| {
                !path.is_empty() && p.get("link").and_then(Value::as_bool) != Some(true)
            })
            .filter_map(|(path, p)| {
                let name = path.rsplit("node_modules/").next()?;
                Some(package(
                    name,
                    p.get("version").and_then(Value::as_str),
                    "npm",
                ))
            })
            .collect();
    }
    let mut out = Vec::new();
    npm_v1(doc.get("dependencies"), &mut out);
    out
}

fn npm_v1(deps: Option<&Value>, out: &mut Vec<Component>) {
    for (name, d) in deps.and_then(Value::as_object).into_iter().flatten() {
        out.push(package(
            name,
            d.get("version").and_then(Value::as_str),
            "npm",
        ));
        npm_v1(d.get("dependencies"), out);
    }
}

/// Splits `name@range` or `@scope/name@npm:range` at the last `@` after the first character.
fn npm_spec_name(spec: &str) -> Option<&str> {
    let at = spec[1..].rfind('@')? + 1;
    Some(&spec[..at])
}

/// Yarn classic and Berry: an unindented `spec, spec:` header followed by an indented
/// `version "x"` or `version: x` line.
fn yarn_lock(text: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(' ') && line.ends_with(':') && !line.starts_with('#') {
            let first = line
                .trim_end_matches(':')
                .split(", ")
                .next()
                .unwrap_or_default();
            let spec = first.trim_matches('"');
            let workspace =
                spec.contains("@workspace:") || spec.contains("@link:") || spec.contains("@file:");
            name = (!workspace && spec != "__metadata")
                .then(|| npm_spec_name(spec))
                .flatten()
                .map(str::to_string);
        } else if let Some(n) = &name {
            let trimmed = line.trim();
            if let Some(v) = trimmed
                .strip_prefix("version ")
                .or(trimmed.strip_prefix("version: "))
            {
                out.push(package(n, Some(v.trim_matches('"')), "npm"));
                name = None;
            }
        }
    }
    out
}

/// pnpm `packages:` keys in the v5 (`/name/1.0.0`), v6 (`/name@1.0.0`) and v9 (`name@1.0.0`)
/// forms, ignoring peer suffixes in parentheses.
fn pnpm_lock(text: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut in_packages = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        let Some(key) = line.strip_prefix("  ").filter(|k| !k.starts_with(' ')) else {
            continue;
        };
        if !in_packages || !key.ends_with(':') {
            continue;
        }
        let key = key
            .trim_end_matches(':')
            .trim_matches(|c| c == '\'' || c == '"');
        let key = key
            .split('(')
            .next()
            .unwrap_or_default()
            .trim_start_matches('/');
        let (name, version) = match npm_spec_name(key) {
            Some(name) => (name, &key[name.len() + 1..]),
            None => match key.rsplit_once('/') {
                Some(parts) => parts,
                None => continue,
            },
        };
        out.push(package(name, Some(version), "npm"));
    }
    out
}

/// `[[package]]` blocks with `name`, `version` and an optional `source` line, as in poetry.lock,
/// uv.lock and Cargo.lock. `keep` decides from the source text (empty when absent).
fn toml_packages(text: &str, ecosystem: &str, keep: fn(&str) -> bool) -> Vec<Component> {
    let mut out = Vec::new();
    let mut block: Option<(String, String, String)> = None;
    let mut flush = |block: &mut Option<(String, String, String)>| {
        if let Some((name, version, source)) = block.take()
            && !name.is_empty()
            && keep(&source)
        {
            out.push(package(&name, Some(&version), ecosystem));
        }
    };
    for line in text.lines() {
        if line.starts_with('[') {
            flush(&mut block);
            if line.trim() == "[[package]]" {
                block = Some(Default::default());
            }
            continue;
        }
        let Some((name, version, source)) = block.as_mut() else {
            continue;
        };
        let value = |prefix: &str| {
            line.strip_prefix(prefix)
                .map(|v| v.trim().trim_matches('"').to_string())
        };
        if let Some(v) = value("name =") {
            *name = v;
        } else if let Some(v) = value("version =") {
            *version = v;
        } else if let Some(v) = value("source =") {
            *source = v;
        }
    }
    flush(&mut block);
    out
}

fn pipfile_lock(doc: &Value) -> Vec<Component> {
    ["default", "develop"]
        .iter()
        .filter_map(|section| doc.get(section).and_then(Value::as_object))
        .flatten()
        .map(|(name, p)| {
            let version = p
                .get("version")
                .and_then(Value::as_str)
                .map(|v| v.trim_start_matches("=="));
            package(name, version, "PyPI")
        })
        .collect()
}

/// Pinned `name==version` lines; unpinned requirements are kept without a version so they are
/// reported as not checked.
fn requirements(text: &str) -> Vec<Component> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim())
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .filter_map(|l| {
            let spec = l.split(';').next().unwrap_or_default().trim();
            let (name, version) = match spec.split_once("==") {
                Some((n, v)) => (n, Some(v.split_whitespace().next().unwrap_or_default())),
                None => (
                    spec.split(['<', '>', '=', '!', '~', ' '])
                        .next()
                        .unwrap_or_default(),
                    None,
                ),
            };
            let name = name.split('[').next().unwrap_or_default();
            (!name.is_empty()).then(|| package(name, version, "PyPI"))
        })
        .collect()
}

fn go_mod(text: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or_default().trim();
        let spec = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if line == "require (" {
            in_block = true;
            continue;
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        if let (Some(module), Some(version)) = (parts.next(), parts.next()) {
            out.push(package(module, Some(version), "Go"));
        }
    }
    out
}

/// Four-space `name (version)` lines under a `GEM` section's `specs:`.
fn gemfile_lock(text: &str) -> Vec<Component> {
    let mut out = Vec::new();
    let mut section = "";
    let mut in_specs = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            section = line.trim();
            in_specs = false;
        } else if line.trim() == "specs:" {
            in_specs = section == "GEM";
        } else if in_specs
            && let Some(spec) = line.strip_prefix("    ").filter(|s| !s.starts_with(' '))
            && let Some((name, version)) = spec.split_once(" (")
        {
            out.push(package(
                name,
                Some(version.trim_end_matches(')')),
                "RubyGems",
            ));
        }
    }
    out
}

fn composer_lock(doc: &Value) -> Vec<Component> {
    ["packages", "packages-dev"]
        .iter()
        .filter_map(|key| doc.get(key).and_then(Value::as_array))
        .flatten()
        .filter_map(|p| {
            let name = p.get("name").and_then(Value::as_str)?;
            Some(package(
                name,
                p.get("version").and_then(Value::as_str),
                "Packagist",
            ))
        })
        .collect()
}

fn nuget_lock(doc: &Value) -> Vec<Component> {
    doc.get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|frameworks| frameworks.values())
        .filter_map(Value::as_object)
        .flatten()
        .filter(|(_, d)| d.get("type").and_then(Value::as_str) != Some("Project"))
        .map(|(name, d)| package(name, d.get("resolved").and_then(Value::as_str), "NuGet"))
        .collect()
}

/// `group:artifact:version=configurations` lines.
fn gradle_lockfile(text: &str) -> Vec<Component> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with("empty="))
        .filter_map(|l| {
            let coordinate = l.split('=').next()?;
            let (artifact, version) = coordinate.rsplit_once(':')?;
            artifact
                .contains(':')
                .then(|| package(artifact, Some(version), "Maven"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(file: &str, bytes: &[u8]) -> Vec<String> {
        let (_, components) = parse(file, bytes).unwrap().unwrap();
        components
            .iter()
            .map(|c| {
                format!(
                    "{} {} {}",
                    c.ecosystem.as_deref().unwrap_or("-"),
                    c.name,
                    c.version.as_deref().unwrap_or("-")
                )
            })
            .collect()
    }

    #[test]
    fn npm_lock_v3_from_npm() {
        let got = names(
            "package-lock.json",
            include_bytes!("../tests/fixtures/lock/package-lock.json"),
        );
        assert_eq!(
            got,
            [
                "npm @babel/helper-validator-identifier 7.22.20",
                "npm lodash 4.17.20"
            ]
        );
    }

    #[test]
    fn npm_lock_v1_walks_nested_dependencies() {
        let doc = br#"{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0"}}}}}"#;
        assert_eq!(
            names("package-lock.json", doc),
            ["npm a 1.0.0", "npm b 2.0.0"]
        );
    }

    #[test]
    fn yarn_classic_and_berry() {
        let classic = b"# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.1.2\"\n  resolved \"https://registry\"\n\nlodash@^4.17.20:\n  version \"4.17.20\"\n";
        assert_eq!(
            names("yarn.lock", classic),
            ["npm @babel/core 7.1.2", "npm lodash 4.17.20"]
        );
        let berry = b"__metadata:\n  version: 8\n\n\"demo@workspace:.\":\n  version: 0.0.0-use.local\n\n\"lodash@npm:^4.17.20\":\n  version: 4.17.21\n";
        assert_eq!(names("yarn.lock", berry), ["npm lodash 4.17.21"]);
    }

    #[test]
    fn pnpm_lock_v6_and_v9_keys() {
        let v9 = b"lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        version: 4.17.20\n\npackages:\n\n  '@babel/core@7.1.2':\n    resolution: {integrity: x}\n\n  lodash@4.17.20:\n    resolution: {integrity: y}\n\nsnapshots:\n\n  lodash@4.17.20: {}\n";
        assert_eq!(
            names("pnpm-lock.yaml", v9),
            ["npm @babel/core 7.1.2", "npm lodash 4.17.20"]
        );
        let v6 = b"lockfileVersion: '6.0'\n\npackages:\n\n  /react-dom@18.2.0(react@18.2.0):\n    resolution: {integrity: z}\n";
        assert_eq!(names("pnpm-lock.yaml", v6), ["npm react-dom 18.2.0"]);
    }

    #[test]
    fn python_lockfiles() {
        let uv = names("uv.lock", include_bytes!("../tests/fixtures/lock/uv.lock"));
        assert!(uv.contains(&"PyPI requests 2.19.0".to_string()));
        assert!(
            uv.iter().all(|n| !n.contains(" demo ")),
            "the virtual project itself is skipped"
        );
        let req = names(
            "requirements.txt",
            include_bytes!("../tests/fixtures/lock/requirements.txt"),
        );
        assert!(req.contains(&"PyPI requests 2.19.0".to_string()));
        let loose = names(
            "requirements-dev.txt",
            b"-r base.txt\nflask[async]==2.0.1 ; python_version >= '3.8'\nrequests>=2.0\n",
        );
        assert_eq!(loose, ["PyPI flask 2.0.1", "PyPI requests -"]);
        let poetry = names("poetry.lock", b"[[package]]\nname = \"django\"\nversion = \"3.2.0\"\ndescription = \"x\"\n\n[metadata]\nlock-version = \"2.0\"\n");
        assert_eq!(poetry, ["PyPI django 3.2.0"]);
        let pipfile = names("Pipfile.lock", br#"{"default":{"requests":{"version":"==2.19.0"}},"develop":{"pytest":{"version":"==7.0.0"}}}"#);
        assert_eq!(pipfile, ["PyPI requests 2.19.0", "PyPI pytest 7.0.0"]);
    }

    #[test]
    fn cargo_lock_skips_workspace_crates() {
        let got = names("Cargo.lock", b"version = 4\n\n[[package]]\nname = \"hyper\"\nversion = \"0.14.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"my-app\"\nversion = \"0.1.0\"\n");
        assert_eq!(got, ["crates.io hyper 0.14.0"]);
    }

    #[test]
    fn go_mod_from_go() {
        let got = names("go.mod", include_bytes!("../tests/fixtures/lock/go.mod"));
        assert_eq!(got, ["Go golang.org/x/net v0.17.0"]);
        let block = names("go.mod", b"module m\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v0.0.0-2020 // indirect\n)\n");
        assert_eq!(got.len() + block.len(), 3);
    }

    #[test]
    fn gemfile_lock_from_bundler_ignores_checksums() {
        let got = names(
            "Gemfile.lock",
            include_bytes!("../tests/fixtures/lock/Gemfile.lock"),
        );
        assert_eq!(got, ["RubyGems rack 2.2.3"]);
    }

    #[test]
    fn composer_nuget_and_gradle() {
        let composer = names("composer.lock", br#"{"packages":[{"name":"symfony/http-kernel","version":"v5.4.0"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}"#);
        assert_eq!(
            composer,
            [
                "Packagist symfony/http-kernel v5.4.0",
                "Packagist phpunit/phpunit 9.5.0"
            ]
        );
        let nuget = names("packages.lock.json", br#"{"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"12.0.1"},"MyLib":{"type":"Project"}}}}"#);
        assert_eq!(nuget, ["NuGet Newtonsoft.Json 12.0.1"]);
        let gradle = names("gradle.lockfile", b"# comment\norg.apache.logging.log4j:log4j-core:2.14.1=compileClasspath\nempty=annotationProcessor\n");
        assert_eq!(gradle, ["Maven org.apache.logging.log4j:log4j-core 2.14.1"]);
    }

    #[test]
    fn other_file_names_are_not_lockfiles() {
        assert!(parse("bom.json", b"{}").is_none());
    }
}
