use std::collections::HashSet;
use std::time::Duration;

use serde::Deserialize;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
struct Cert {
    common_name: String,
    name_value: String,
}

pub async fn get_subdomains(domain: &str) -> Result<HashSet<String>, String> {
    let url = format!("https://crt.sh/json?q={domain}&exclude=expired");
    let certs: Vec<Cert> = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to build client: {e}"))?
        .get(url)
        .send()
        .await
        .map_err(|e| format!("crt.sh request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("crt.sh response could not be parsed: {e}"))?;

    let mut sub_domains = HashSet::new();

    for cert in certs {
        if !cert.common_name.is_empty() {
            sub_domains.insert(cert.common_name);
        }
        if !cert.name_value.is_empty() {
            for name in cert.name_value.split('\n') {
                if name.starts_with("*.") {
                    continue;
                }
                sub_domains.insert(name.trim().to_string());
            }
        }
    }
    Ok(sub_domains)
}
