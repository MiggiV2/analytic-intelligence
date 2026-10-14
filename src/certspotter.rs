use std::collections::HashSet;
use std::time::Duration;

use serde::Deserialize;

// Cert Spotter free tier is rate limited and intended for personal use,
// so stay conservative: one request per second (docs: https://sslmate.com/certspotter)
const REQUEST_DELAY: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Deserialize)]
struct Issuance {
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
}

/// Fetches subdomains from Cert Spotter (keyless free tier).
/// Paginates via `after=<last id>` and sleeps between requests to respect the rate limit.
pub async fn get_subdomains(
    domain: &str,
    log: impl Fn(String),
) -> Result<HashSet<String>, String> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to build client: {e}"))?;

    let mut sub_domains = HashSet::new();
    let mut after = String::new();
    let mut page = 0;

    loop {
        let mut url = format!(
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        );
        if !after.is_empty() {
            url.push_str(&format!("&after={after}"));
        }

        let response = client.get(&url).send().await;
        page += 1;
        log(format!("Cert Spotter: requesting page {page}"));

        let issuances: Vec<Issuance> = match response {
            Ok(res) if res.status().is_success() => {
                res.json().await.map_err(|e| format!("invalid response: {e}"))?
            }
            Ok(res) => {
                return Err(format!(
                    "Cert Spotter returned HTTP {}{}",
                    res.status(),
                    if res.status().as_u16() == 429 {
                        " (rate limited, try again later)"
                    } else {
                        ""
                    }
                ))
            }
            Err(err) => return Err(format!("Cert Spotter request failed: {err}")),
        };

        if issuances.is_empty() {
            break;
        }

        for issuance in &issuances {
            for name in &issuance.dns_names {
                if name.starts_with("*.") {
                    continue;
                }
                sub_domains.insert(name.trim().to_string());
            }
            after = issuance.id.clone();
        }

        // Rate limit: the free tier allows roughly one request per second
        tokio::time::sleep(REQUEST_DELAY).await;
    }

    Ok(sub_domains)
}
