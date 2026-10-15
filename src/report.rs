use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub domain: String,
    pub scanned_at: DateTime<FixedOffset>,
    pub complete: bool,
    pub source: Option<String>,
    pub mail_server: Option<String>,
    pub hosts: Vec<HostReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostReport {
    pub domain: String,
    pub state: HostState,
    pub skip_reason: Option<String>,
    pub ip: Option<String>,
    pub ptr: Option<String>,
    pub location: Option<String>,
    pub title: Option<String>,
    pub tech: Vec<String>,
    pub security_headers: Option<SecurityHeaders>,
    pub tls: Option<TlsReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Up,
    Down,
    Skipped,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub present: usize,
    pub total: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsReport {
    pub issuer: String,
    pub days_left: i64,
    pub self_signed: bool,
}

pub fn to_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).expect("report is always serializable")
}

pub fn to_markdown(report: &ScanReport) -> String {
    let mut md = format!("# Scan report: {}\n\n", escape_markdown(&report.domain));
    if !report.complete {
        md.push_str(
            "> **Note:** exported before the scan had finished, results are incomplete.\n\n",
        );
    }
    md.push_str(&summary(report));
    md.push_str("\n## Overview\n\n");
    md.push_str("| State | Domain | IP | PTR | Org / Location | TLS | Sec | Title |\n");
    md.push_str("|---|---|---|---|---|---|---|---|\n");
    for host in &report.hosts {
        md.push_str(&overview_row(host));
    }

    let checked: Vec<&HostReport> = report
        .hosts
        .iter()
        .filter(|host| host.state != HostState::Skipped)
        .collect();
    if !checked.is_empty() {
        md.push_str("\n## Details\n");
        for host in checked {
            md.push_str(&details(host));
        }
    }
    md
}

pub fn write(report: &ScanReport, dir: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let stem = format!(
        "{}-{}",
        sanitize_file_name(&report.domain),
        report.scanned_at.format("%Y%m%d-%H%M")
    );
    let json_path = dir.join(format!("{stem}.json"));
    let md_path = dir.join(format!("{stem}.md"));
    std::fs::write(&json_path, to_json(report))?;
    std::fs::write(&md_path, to_markdown(report))?;
    Ok((json_path, md_path))
}

fn summary(report: &ScanReport) -> String {
    let count = |state: HostState| report.hosts.iter().filter(|h| h.state == state).count();
    let mut lines = vec![format!(
        "- **Scanned at:** {}",
        report.scanned_at.format("%Y-%m-%d %H:%M:%S %:z")
    )];
    if let Some(source) = &report.source {
        lines.push(format!("- **Source:** {}", escape_markdown(source)));
    }
    lines.push(format!(
        "- **Mail server:** {}",
        escape_markdown(report.mail_server.as_deref().unwrap_or("none found"))
    ));
    let mut hosts = format!(
        "- **Hosts:** {} (up {}, down {}, skipped {}",
        report.hosts.len(),
        count(HostState::Up),
        count(HostState::Down),
        count(HostState::Skipped)
    );
    let pending = count(HostState::Pending);
    if pending > 0 {
        hosts.push_str(&format!(", pending {pending}"));
    }
    hosts.push(')');
    lines.push(hosts);
    lines.join("\n") + "\n"
}

fn overview_row(host: &HostReport) -> String {
    let domain = match &host.skip_reason {
        Some(reason) => format!("{} ({reason})", host.domain),
        None => host.domain.clone(),
    };
    let security = host
        .security_headers
        .as_ref()
        .map(|sec| format!("{}/{}", sec.present, sec.total))
        .unwrap_or_default();
    let cells = [
        state_label(host.state).to_string(),
        domain,
        host.ip.clone().unwrap_or_default(),
        host.ptr.clone().unwrap_or_default(),
        host.location.clone().unwrap_or_default(),
        host.tls.as_ref().map(tls_short).unwrap_or_default(),
        security,
        host.title.clone().unwrap_or_default(),
    ];
    let cells: Vec<String> = cells.iter().map(|cell| escape_markdown(cell)).collect();
    format!("| {} |\n", cells.join(" | "))
}

fn details(host: &HostReport) -> String {
    let mut md = format!("\n### {}\n\n", escape_markdown(&host.domain));
    md.push_str(&format!("- **State:** {}\n", state_label(host.state)));
    if let Some(ip) = host.ip.as_deref().map(escape_markdown) {
        match host.ptr.as_deref().map(escape_markdown) {
            Some(ptr) => md.push_str(&format!("- **IP:** {ip} (PTR: {ptr})\n")),
            None => md.push_str(&format!("- **IP:** {ip}\n")),
        }
    }
    if let Some(location) = host.location.as_deref().map(escape_markdown) {
        md.push_str(&format!("- **Org / Location:** {location}\n"));
    }
    if let Some(tls) = &host.tls {
        md.push_str(&format!("- **TLS:** {}\n", escape_markdown(&tls_long(tls))));
    }
    if let Some(sec) = &host.security_headers {
        md.push_str(&format!(
            "- **Security headers:** {}/{} present\n",
            sec.present, sec.total
        ));
    }
    if !host.tech.is_empty() {
        md.push_str(&format!(
            "- **Tech:** {}\n",
            escape_markdown(&host.tech.join(", "))
        ));
    }
    if let Some(title) = &host.title {
        md.push_str(&format!("- **Title:** {}\n", escape_markdown(title)));
    }
    md
}

fn state_label(state: HostState) -> &'static str {
    match state {
        HostState::Up => "UP",
        HostState::Down => "DOWN",
        HostState::Skipped => "SKIP",
        HostState::Pending => "WAIT",
    }
}

fn tls_short(tls: &TlsReport) -> String {
    let validity = if tls.days_left < 0 {
        "expired".to_string()
    } else {
        format!("{} days", tls.days_left)
    };
    with_self_signed(validity, tls)
}

fn tls_long(tls: &TlsReport) -> String {
    let validity = if tls.days_left < 0 {
        format!("expired {} days ago", -tls.days_left)
    } else {
        format!("expires in {} days", tls.days_left)
    };
    with_self_signed(format!("{}, {validity}", tls.issuer), tls)
}

fn with_self_signed(text: String, tls: &TlsReport) -> String {
    if tls.self_signed {
        format!("{text}, self-signed")
    } else {
        text
    }
}

/// Page titles, PTR records and certificate issuers come from the scanned hosts,
/// so they must not be able to inject links, images or HTML into the report
fn escape_markdown(value: &str) -> String {
    let single_line = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut escaped = String::with_capacity(single_line.len());
    for c in single_line.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '!' | '|' | '&'
        ) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

fn sanitize_file_name(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(domain: &str, state: HostState) -> HostReport {
        HostReport {
            domain: domain.to_string(),
            state,
            skip_reason: None,
            ip: None,
            ptr: None,
            location: None,
            title: None,
            tech: Vec::new(),
            security_headers: None,
            tls: None,
        }
    }

    fn sample_report() -> ScanReport {
        let mut up = host("www.example.com", HostState::Up);
        up.ip = Some("93.184.215.14".to_string());
        up.ptr = Some("edge.example.net".to_string());
        up.location = Some("Edgecast, US, Los Angeles".to_string());
        up.title = Some("Example | Home".to_string());
        up.tech = vec!["nginx".to_string(), "PHP".to_string()];
        up.security_headers = Some(SecurityHeaders {
            present: 3,
            total: 5,
        });
        up.tls = Some(TlsReport {
            issuer: "CN=R11, O=Let's Encrypt, C=US".to_string(),
            days_left: 66,
            self_signed: false,
        });
        let mut skipped = host("intranet.example.com", HostState::Skipped);
        skipped.skip_reason = Some("local address".to_string());

        ScanReport {
            domain: "example.com".to_string(),
            scanned_at: DateTime::parse_from_rfc3339("2026-10-15T14:03:27+02:00").unwrap(),
            complete: true,
            source: Some("crt.sh".to_string()),
            mail_server: Some("mx.example.com".to_string()),
            hosts: vec![up, host("old.example.com", HostState::Down), skipped],
        }
    }

    #[test]
    fn json_round_trips_the_full_report() {
        // given
        let report = sample_report();

        // when
        let json = to_json(&report);

        // then
        let parsed: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, report);
        assert!(json.contains("\"state\": \"up\""));
        assert!(json.contains("\"scanned_at\": \"2026-10-15T14:03:27+02:00\""));
    }

    #[test]
    fn markdown_contains_summary_overview_and_details() {
        // given
        let report = sample_report();

        // when
        let markdown = to_markdown(&report);

        // then
        assert!(markdown.starts_with("# Scan report: example.com\n"));
        assert!(markdown.contains("**Source:** crt.sh"));
        assert!(markdown.contains("**Mail server:** mx.example.com"));
        assert!(markdown.contains("**Hosts:** 3 (up 1, down 1, skipped 1)"));
        assert!(markdown.contains(
            "| UP | www.example.com | 93.184.215.14 | edge.example.net | Edgecast, US, Los Angeles | 66 days | 3/5 | Example \\| Home |"
        ));
        assert!(markdown.contains("| SKIP | intranet.example.com (local address) |"));
        assert!(markdown.contains("### www.example.com"));
        assert!(markdown.contains("- **Tech:** nginx, PHP"));
        assert!(markdown.contains("- **TLS:** CN=R11, O=Let's Encrypt, C=US, expires in 66 days"));
        assert!(!markdown.contains("### intranet.example.com"));
        assert!(!markdown.contains("exported before the scan"));
    }

    #[test]
    fn markdown_escapes_untrusted_host_data() {
        // given
        let mut report = sample_report();
        let mut hostile = host("evil.example.com", HostState::Up);
        hostile.title = Some("![x](http://tracker/p.png) <b>`a\\|b`</b>".to_string());
        hostile.ip = Some("203.0.113.7".to_string());
        hostile.ptr = Some("[click](https://evil)".to_string());
        hostile.tech = vec!["*bold*".to_string()];
        report.hosts = vec![hostile];

        // when
        let markdown = to_markdown(&report);

        // then
        let escaped_title = r"\!\[x\](http://tracker/p.png) \<b\>\`a\\\|b\`\</b\>";
        assert!(markdown.contains(&format!("| {escaped_title} |")));
        assert!(markdown.contains(&format!("- **Title:** {escaped_title}")));
        assert!(markdown.contains(r"PTR: \[click\](https://evil)"));
        assert!(markdown.contains(r"- **Tech:** \*bold\*"));
        assert!(!markdown.contains("<b>"));
        assert!(!markdown.contains("[click]"));
    }

    #[test]
    fn markdown_warns_when_scan_was_not_finished() {
        // given
        let mut report = sample_report();
        report.complete = false;

        // when
        let markdown = to_markdown(&report);

        // then
        assert!(markdown.contains("> **Note:** exported before the scan had finished"));
    }

    #[test]
    fn markdown_flags_expired_and_self_signed_certificates() {
        // given
        let mut report = sample_report();
        let mut expired = host("expired.example.com", HostState::Up);
        expired.tls = Some(TlsReport {
            issuer: "CN=expired.example.com".to_string(),
            days_left: -3,
            self_signed: true,
        });
        report.hosts = vec![expired];

        // when
        let markdown = to_markdown(&report);

        // then
        assert!(markdown.contains("| expired, self-signed |"));
        assert!(
            markdown.contains("- **TLS:** CN=expired.example.com, expired 3 days ago, self-signed")
        );
    }

    #[test]
    fn writes_json_and_markdown_named_after_domain_and_timestamp() {
        // given
        let dir = tempfile::tempdir().unwrap();
        let mut report = sample_report();
        report.domain = "ex/ample.com".to_string();

        // when
        let (json_path, md_path) = write(&report, dir.path()).unwrap();

        // then
        assert_eq!(
            json_path,
            dir.path().join("ex_ample.com-20261015-1403.json")
        );
        assert_eq!(md_path, dir.path().join("ex_ample.com-20261015-1403.md"));
        let parsed: ScanReport =
            serde_json::from_str(&std::fs::read_to_string(json_path).unwrap()).unwrap();
        assert_eq!(parsed, report);
        assert!(
            std::fs::read_to_string(md_path)
                .unwrap()
                .starts_with("# Scan report")
        );
    }
}
