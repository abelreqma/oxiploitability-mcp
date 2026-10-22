use schemars::JsonSchema;
use serde::Serialize;

/// What an attacker gains from a vulnerability, derived from its CWE ids, description, CISA KEV
/// entry or CVSS vector rather than stated by any source.
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct Impact {
    /// RCE, Malicious code, Privilege escalation, Sandbox escape, Auth bypass, Access control
    /// bypass, Security feature bypass, SQL injection, Memory corruption, SSRF, XXE, Path
    /// traversal, Arbitrary file upload, Request smuggling, Information disclosure, Data
    /// tampering, XSS, CSRF, Open redirect, DoS or Cryptographic weakness.
    pub kind: String,
    /// The CWE id, description phrase, CISA KEV phrase or CVSS impact metric the impact was
    /// derived from.
    pub evidence: String,
}

/// Impact kinds, most severe first, with the CWE ids and lowercase description phrases that
/// indicate each.
const KINDS: &[(&str, &[u32], &[&str])] = &[
    (
        "RCE",
        &[77, 78, 94, 95, 96, 502, 917, 1336],
        &[
            "code execution",
            "execute code",
            "execute arbitrary code",
            "execution of arbitrary code",
            "arbitrary python code",
            "execute arbitrary commands",
            "execution of arbitrary commands",
            "command execution",
            "command injection",
            "code injection",
            "deserialization of untrusted data",
        ],
    ),
    (
        "Malicious code",
        &[506, 507, 508, 510, 511, 512],
        &["embedded malicious code", "backdoor", "malicious code"],
    ),
    (
        "Privilege escalation",
        &[250, 266, 269, 274],
        &[
            "privilege escalation",
            "improper privilege management",
            "escalate privileges",
            "escalation of privilege",
            "elevation of privilege",
            "elevate privileges",
            "gain privileges",
            "gain root",
        ],
    ),
    (
        "Sandbox escape",
        &[],
        &["sandbox escape", "sandbox breakout", "escape the sandbox"],
    ),
    (
        "Auth bypass",
        &[287, 288, 290, 294, 303, 305, 306, 798, 1390],
        &[
            "authentication bypass",
            "bypass authentication",
            "bypass the authentication",
            "improper authentication",
            "missing authentication",
            "hard-coded credentials",
            "hardcoded credentials",
            "hard-coded password",
            "default password",
            "weak authentication",
        ],
    ),
    (
        "Access control bypass",
        &[284, 285, 639, 732, 862, 863],
        &[
            "authorization bypass",
            "bypass authorization",
            "access control bypass",
            "bypass access control",
            "improper access control",
            "missing authorization",
            "incorrect authorization",
            "improper authorization",
        ],
    ),
    (
        "Security feature bypass",
        &[693],
        &[
            "security feature bypass",
            "security control bypass",
            "protection mechanism failure",
        ],
    ),
    ("SQL injection", &[89, 564], &["sql injection"]),
    (
        "Memory corruption",
        &[119, 120, 121, 122, 415, 416, 787, 843],
        &[
            "type confusion",
            "buffer overflow",
            "heap overflow",
            "use-after-free",
            "use after free",
            "out-of-bounds write",
            "memory corruption",
            "double free",
        ],
    ),
    ("SSRF", &[918], &["server-side request forgery", "ssrf"]),
    ("XXE", &[611, 776], &["xml external entit"]),
    (
        "Path traversal",
        &[22, 23, 35, 36, 59, 73],
        &[
            "path traversal",
            "directory traversal",
            "local file inclusion",
            "link following",
        ],
    ),
    (
        "Arbitrary file upload",
        &[434],
        &[
            "unrestricted upload",
            "unrestricted file upload",
            "arbitrary file upload",
            "upload arbitrary files",
        ],
    ),
    (
        "Request smuggling",
        &[444],
        &["request smuggling", "response splitting"],
    ),
    (
        "Information disclosure",
        &[125, 200, 201, 209, 312, 319, 359, 522, 532, 538, 552],
        &[
            "information disclosure",
            "disclosure of sensitive",
            "sensitive information",
            "information leak",
            "obtain sensitive",
            "out-of-bounds read",
            "arbitrary file read",
            "read arbitrary files",
            "accessible to external parties",
        ],
    ),
    ("Data tampering", &[], &[]),
    (
        "XSS",
        // CWE-80 to CWE-87 are the XSS variants under CWE-79.
        &[79, 80, 81, 82, 83, 84, 85, 86, 87],
        &[
            "cross-site scripting",
            "cross site scripting",
            "xss",
            "encoded uri schemes in a web page",
        ],
    ),
    (
        "CSRF",
        &[352],
        &[
            "cross-site request forgery",
            "cross site request forgery",
            "csrf",
        ],
    ),
    ("Open redirect", &[601], &["open redirect"]),
    (
        "DoS",
        &[400, 401, 404, 407, 476, 674, 770, 789, 834, 835, 1333],
        &[
            "denial of service",
            "denial-of-service",
            "resource exhaustion",
            "infinite loop",
            "null pointer dereference",
            "crash",
        ],
    ),
    (
        "Cryptographic weakness",
        &[295, 311, 326, 327, 328, 330, 338, 347],
        &[
            "certificate validation",
            "weak cipher",
            "weak encryption",
            "signature verification",
            "missing encryption",
        ],
    ),
];

/// The impacts `cwes` and `description` indicate, most severe first, one per kind. A CWE match
/// is preferred over a description phrase as the evidence. When neither indicates anything, the
/// CVSS vector's confidentiality, integrity and availability metrics decide.
pub fn classify(cwes: &[String], description: &str, cvss_vector: Option<&str>) -> Vec<Impact> {
    let found = by_weakness(cwes, description, "description");
    match (found.is_empty(), cvss_vector) {
        (true, Some(vector)) => by_cvss(vector),
        _ => found,
    }
}

/// Classifies the text of another source, such as a CISA KEV entry, when `impacts` holds
/// nothing more specific than CVSS-derived entries. Its phrases are labelled with `source` in
/// the evidence.
pub fn refine(impacts: &mut Vec<Impact>, source: &str, text: &str) {
    if impacts.iter().any(|i| !from_cvss(i)) {
        return;
    }
    let found = by_weakness(&[], text, source);
    if !found.is_empty() {
        *impacts = found;
    }
}

fn from_cvss(i: &Impact) -> bool {
    i.evidence.starts_with("CVSS ")
}

/// Information disclosure, Data tampering and DoS for each of the confidentiality, integrity and
/// availability metrics (`C`, `I`, `A` in CVSS 2 and 3, `VC`, `VI`, `VA` in CVSS 4) that is not
/// `N`.
fn by_cvss(vector: &str) -> Vec<Impact> {
    let metric = |keys: [&str; 2]| {
        vector
            .split('/')
            .filter_map(|part| part.split_once(':'))
            .find(|(k, _)| keys.contains(k))
    };
    [
        ("Information disclosure", ["C", "VC"]),
        ("Data tampering", ["I", "VI"]),
        ("DoS", ["A", "VA"]),
    ]
    .into_iter()
    .filter_map(|(kind, keys)| {
        let (k, v) = metric(keys).filter(|(_, v)| *v != "N")?;
        Some(Impact {
            kind: kind.to_string(),
            evidence: format!("CVSS {k}:{v}"),
        })
    })
    .collect()
}

fn by_weakness(cwes: &[String], description: &str, label: &str) -> Vec<Impact> {
    let text = description.to_lowercase();
    KINDS
        .iter()
        .filter_map(|(kind, ids, phrases)| {
            let by_cwe = cwes.iter().find(|c| {
                c.strip_prefix("CWE-")
                    .and_then(|n| n.parse::<u32>().ok())
                    .is_some_and(|n| ids.contains(&n))
            });
            let evidence = match by_cwe {
                Some(cwe) => cwe.clone(),
                None => format!(
                    "{label}: {}",
                    phrases.iter().find(|p| starts_word(&text, p))?
                ),
            };
            Some(Impact {
                kind: kind.to_string(),
                evidence,
            })
        })
        .collect()
}

/// Whether `phrase` occurs in `text` at the start of a word, so `xss` does not match inside
/// another word while `crash` still matches `crashes`.
fn starts_word(text: &str, phrase: &str) -> bool {
    text.match_indices(phrase).any(|(i, _)| {
        text[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric())
    })
}

/// Combines two classifications of the same vulnerability, as from two advisories for one CVE,
/// keeping the most-severe-first order. CVSS-derived impacts are dropped once a CWE id or
/// description phrase indicates any, matching `classify`.
pub fn merge(into: &mut Vec<Impact>, more: Vec<Impact>) {
    for m in more {
        if !into.iter().any(|i| i.kind == m.kind) {
            into.push(m);
        }
    }
    if into.iter().any(|i| !from_cvss(i)) {
        into.retain(|i| !from_cvss(i));
    }
    into.sort_by_key(|i| rank(&i.kind));
}

/// Every kind across several vulnerabilities, most severe first.
pub fn kinds<'a>(lists: impl IntoIterator<Item = &'a [Impact]>) -> Vec<String> {
    let mut all: Vec<String> = Vec::new();
    for i in lists.into_iter().flatten() {
        if !all.contains(&i.kind) {
            all.push(i.kind.clone());
        }
    }
    all.sort_by_key(|k| rank(k));
    all
}

fn rank(kind: &str) -> Option<usize> {
    KINDS.iter().position(|(k, _, _)| *k == kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(impacts: &[Impact]) -> Vec<&str> {
        impacts.iter().map(|i| i.kind.as_str()).collect()
    }

    #[test]
    fn cwes_and_description_phrases_map_to_impacts_most_severe_first() {
        let log4shell = classify(
            &[
                "CWE-20".into(),
                "CWE-400".into(),
                "CWE-502".into(),
                "CWE-917".into(),
            ],
            "An attacker who can control log messages can execute arbitrary code.",
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        );
        assert_eq!(
            names(&log4shell),
            ["RCE", "DoS"],
            "CVSS is not consulted when a CWE or phrase matches"
        );
        assert_eq!(log4shell[0].evidence, "CWE-502");

        let described = classify(&[], "A crafted request causes a Denial of Service.", None);
        assert_eq!(names(&described), ["DoS"]);
        assert_eq!(described[0].evidence, "description: denial of service");

        let sandbox = classify(
            &[],
            "An attacker that controls the content of a template can execute arbitrary Python code.",
            None,
        );
        assert_eq!(names(&sandbox), ["RCE"]);
        assert_eq!(
            names(&classify(&[], "Stored XSS in comments.", None)),
            ["XSS"]
        );
        assert_eq!(names(&classify(&[], "The server crashes.", None)), ["DoS"]);
        assert!(
            classify(&[], "The noxss flag and the anticsrf module.", None).is_empty(),
            "a phrase inside another word does not match"
        );
        assert_eq!(
            names(&classify(
                &[],
                "str.format_map allows a sandbox escape.",
                None
            )),
            ["Sandbox escape"]
        );
        assert_eq!(
            names(&classify(&["CWE-522".into()], "", None)),
            ["Information disclosure"]
        );

        assert!(
            classify(
                &["CWE-20".into(), "NVD-CWE-noinfo".into()],
                "Improper input.",
                None
            )
            .is_empty()
        );
    }

    #[test]
    fn kev_vulnerability_names_map_to_impacts() {
        for (name, kind) in [
            (
                "Microsoft Windows SmartScreen Security Feature Bypass Vulnerability",
                "Security feature bypass",
            ),
            (
                "3CX Desktop App Embedded Malicious Code Vulnerability",
                "Malicious code",
            ),
            (
                "Linux Kernel Improper Privilege Management Vulnerability",
                "Privilege escalation",
            ),
            (
                "Telerik UI Unrestricted File Upload Vulnerability",
                "Arbitrary file upload",
            ),
            (
                "Zimbra Collaboration Local File Inclusion Vulnerability",
                "Path traversal",
            ),
            (
                "Citrix ShareFile Arbitrary File Read Vulnerability",
                "Information disclosure",
            ),
            (
                "Hikvision Insecure Default Password Vulnerability",
                "Auth bypass",
            ),
            (
                "Microsoft SharePoint Weak Authentication Vulnerability",
                "Auth bypass",
            ),
            (
                "Plex Media Server Improper Neutralization of Encoded URI Schemes in a Web Page Vulnerability",
                "XSS",
            ),
            (
                "Atlassian Multiple Products Files or Directories Accessible to External Parties Vulnerability",
                "Information disclosure",
            ),
            (
                "Apache Tomcat Missing Encryption of Sensitive Data Vulnerability",
                "Cryptographic weakness",
            ),
        ] {
            let mut impacts = Vec::new();
            refine(&mut impacts, "CISA KEV", name);
            assert_eq!(names(&impacts), [kind], "{name}");
        }
        let mut unspecified = Vec::new();
        refine(
            &mut unspecified,
            "CISA KEV",
            "Oracle WebLogic Server Unspecified Vulnerability",
        );
        assert!(unspecified.is_empty(), "no phrase is invented");
    }

    #[test]
    fn kev_text_replaces_a_cvss_fallback_but_not_a_specific_impact() {
        let kev = "Microsoft Windows SMB Remote Code Execution Vulnerability. Contains an unspecified flaw.";
        let mut generic = classify(
            &[],
            "",
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        );
        refine(&mut generic, "CISA KEV", kev);
        assert_eq!(names(&generic), ["RCE"]);
        assert_eq!(generic[0].evidence, "CISA KEV: code execution");

        let mut specific = classify(&["CWE-79".into()], "", None);
        refine(&mut specific, "CISA KEV", kev);
        assert_eq!(names(&specific), ["XSS"], "a CWE match is kept");

        let mut none = Vec::new();
        refine(
            &mut none,
            "CISA KEV",
            "Ivanti Missing Authentication Vulnerability.",
        );
        assert_eq!(names(&none), ["Auth bypass"]);
        assert_eq!(
            names(&classify(&["CWE-843".into()], "", None)),
            ["Memory corruption"]
        );
        assert_eq!(
            names(&classify(&[], "Allows unrestricted upload of files.", None)),
            ["Arbitrary file upload"]
        );
    }

    #[test]
    fn cvss_impact_metrics_decide_when_nothing_else_matches() {
        let v3 = classify(
            &["CWE-670".into()],
            "Verification stays disabled.",
            Some("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N"),
        );
        assert_eq!(names(&v3), ["Information disclosure", "Data tampering"]);
        assert_eq!(v3[0].evidence, "CVSS C:H");
        let v4 = classify(
            &[],
            "",
            Some("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"),
        );
        assert_eq!(names(&v4), ["DoS"]);
        assert_eq!(v4[0].evidence, "CVSS VA:H");
        let v2 = classify(&[], "", Some("AV:N/AC:L/Au:N/C:P/I:N/A:N"));
        assert_eq!(names(&v2), ["Information disclosure"]);
        assert!(
            classify(
                &[],
                "",
                Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
            )
            .is_empty()
        );
    }

    #[test]
    fn merge_adds_missing_kinds_in_severity_order() {
        let mut impacts = classify(&["CWE-400".into()], "", None);
        merge(
            &mut impacts,
            classify(&["CWE-787".into(), "CWE-835".into()], "", None),
        );
        assert_eq!(names(&impacts), ["Memory corruption", "DoS"]);

        let cvss_only = classify(
            &[],
            "",
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        );
        let mut same = cvss_only.clone();
        merge(&mut same, classify(&["CWE-79".into()], "", None));
        assert_eq!(
            names(&same),
            ["XSS"],
            "a CWE match replaces the CVSS fallback"
        );
        assert_eq!(
            kinds([impacts.as_slice(), cvss_only.as_slice()]),
            [
                "Memory corruption",
                "Information disclosure",
                "Data tampering",
                "DoS"
            ],
            "separate vulnerabilities keep every kind"
        );
        assert_eq!(impacts[1].evidence, "CWE-400");
    }
}
