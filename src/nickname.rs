/// Widely used names for vulnerabilities, which CVE and NVD records do not contain.
const NICKNAMES: &[(&str, &str, &[&str])] = &[
    (
        "eternalblue",
        "EternalBlue (MS17-010)",
        &[
            "CVE-2017-0143",
            "CVE-2017-0144",
            "CVE-2017-0145",
            "CVE-2017-0146",
            "CVE-2017-0147",
            "CVE-2017-0148",
        ],
    ),
    (
        "ms17010",
        "MS17-010",
        &[
            "CVE-2017-0143",
            "CVE-2017-0144",
            "CVE-2017-0145",
            "CVE-2017-0146",
            "CVE-2017-0147",
            "CVE-2017-0148",
        ],
    ),
    ("bluekeep", "BlueKeep", &["CVE-2019-0708"]),
    (
        "log4shell",
        "Log4Shell",
        &["CVE-2021-44228", "CVE-2021-45046"],
    ),
    ("heartbleed", "Heartbleed", &["CVE-2014-0160"]),
    (
        "shellshock",
        "Shellshock",
        &["CVE-2014-6271", "CVE-2014-7169"],
    ),
    ("spring4shell", "Spring4Shell", &["CVE-2022-22965"]),
    (
        "proxylogon",
        "ProxyLogon",
        &[
            "CVE-2021-26855",
            "CVE-2021-26857",
            "CVE-2021-26858",
            "CVE-2021-27065",
        ],
    ),
    (
        "proxyshell",
        "ProxyShell",
        &["CVE-2021-34473", "CVE-2021-34523", "CVE-2021-31207"],
    ),
    (
        "proxynotshell",
        "ProxyNotShell",
        &["CVE-2022-41040", "CVE-2022-41082"],
    ),
    (
        "printnightmare",
        "PrintNightmare",
        &["CVE-2021-34527", "CVE-2021-1675"],
    ),
    ("zerologon", "Zerologon", &["CVE-2020-1472"]),
    ("dirtycow", "Dirty COW", &["CVE-2016-5195"]),
    ("dirtypipe", "Dirty Pipe", &["CVE-2022-0847"]),
    ("regresshion", "regreSSHion", &["CVE-2024-6387"]),
    ("citrixbleed", "Citrix Bleed", &["CVE-2023-4966"]),
    ("citrixbleed2", "Citrix Bleed 2", &["CVE-2025-5777"]),
    ("follina", "Follina", &["CVE-2022-30190"]),
    ("smbghost", "SMBGhost", &["CVE-2020-0796"]),
    ("poodle", "POODLE", &["CVE-2014-3566"]),
    ("ghost", "GHOST", &["CVE-2015-0235"]),
    ("baronsamedit", "Baron Samedit", &["CVE-2021-3156"]),
    ("pwnkit", "PwnKit", &["CVE-2021-4034"]),
    ("looneytunables", "Looney Tunables", &["CVE-2023-4911"]),
    ("text4shell", "Text4Shell", &["CVE-2022-42889"]),
    ("rapidreset", "HTTP/2 Rapid Reset", &["CVE-2023-44487"]),
    (
        "moveit",
        "MOVEit Transfer SQL injection",
        &["CVE-2023-34362"],
    ),
    ("sambacry", "SambaCry", &["CVE-2017-7494"]),
    ("drupalgeddon2", "Drupalgeddon2", &["CVE-2018-7600"]),
    ("imagetragick", "ImageTragick", &["CVE-2016-3714"]),
    ("meltdown", "Meltdown", &["CVE-2017-5754"]),
    ("spectre", "Spectre", &["CVE-2017-5753", "CVE-2017-5715"]),
    ("terrapin", "Terrapin", &["CVE-2023-48795"]),
    ("xzbackdoor", "XZ Utils backdoor", &["CVE-2024-3094"]),
    ("xzutilsbackdoor", "XZ Utils backdoor", &["CVE-2024-3094"]),
    ("leakyvessels", "Leaky Vessels", &["CVE-2024-21626"]),
    ("petitpotam", "PetitPotam", &["CVE-2021-36942"]),
    ("hivenightmare", "HiveNightmare", &["CVE-2021-36934"]),
    ("serioussam", "SeriousSAM", &["CVE-2021-36934"]),
];

/// The display name and CVE ids for a vulnerability nickname such as "EternalBlue" or
/// "Dirty Pipe", matched ignoring case, spaces and punctuation.
pub fn lookup(name: &str) -> Option<(&'static str, &'static [&'static str])> {
    let key: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    NICKNAMES
        .iter()
        .find(|(k, _, _)| *k == key)
        .map(|(_, display, ids)| (*display, *ids))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::CveId;

    #[test]
    fn matches_ignoring_case_spaces_and_punctuation() {
        assert_eq!(lookup("EternalBlue").unwrap().1.len(), 6);
        assert_eq!(lookup("Dirty-Pipe").unwrap().1, ["CVE-2022-0847"]);
        assert_eq!(lookup("regreSSHion").unwrap().1, ["CVE-2024-6387"]);
        assert!(lookup("nginx").is_none());
    }

    #[test]
    fn every_entry_is_a_valid_cve_id() {
        for (key, _, ids) in NICKNAMES {
            assert!(!ids.is_empty(), "{key}");
            for id in *ids {
                assert!(CveId::parse(id).is_ok(), "{key}: {id}");
            }
        }
    }
}
