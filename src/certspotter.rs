use std::collections::HashSet;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::RETRY_AFTER;
use serde::Deserialize;

// Cert Spotter free tier is rate limited and intended for personal use,
// so stay conservative: one request per second (docs: https://sslmate.com/certspotter)
const REQUEST_DELAY: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRY_WAIT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 3;

#[derive(Deserialize)]
struct Issuance {
    id: String,
    #[serde(default)]
    dns_names: Vec<String>,
}

const API_URL: &str = "https://api.certspotter.com";

/// Fetches subdomains from Cert Spotter (keyless free tier).
/// Paginates via `after=<last id>` and sleeps between requests to respect the rate limit.
pub async fn get_subdomains(domain: &str, log: impl Fn(String)) -> Result<HashSet<String>, String> {
    fetch_subdomains(API_URL, domain, REQUEST_DELAY, log).await
}

async fn fetch_subdomains(
    base_url: &str,
    domain: &str,
    request_delay: Duration,
    log: impl Fn(String),
) -> Result<HashSet<String>, String> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|e| format!("failed to build client: {e}"))?;

    let mut sub_domains = HashSet::new();
    let mut after = String::new();
    let mut page = 0;
    let mut retries = 0;

    loop {
        let mut url = format!(
            "{base_url}/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        );
        if !after.is_empty() {
            url.push_str(&format!("&after={after}"));
        }

        if retries == 0 {
            page += 1;
        }
        log(format!("Cert Spotter: requesting page {page}"));
        let response = client.get(&url).send().await;

        let issuances: Vec<Issuance> = match response {
            Ok(res) if res.status().is_success() => {
                retries = 0;
                res.json()
                    .await
                    .map_err(|e| format!("invalid response: {e}"))?
            }
            Ok(res) if res.status() == StatusCode::TOO_MANY_REQUESTS => match retry_after(&res) {
                Some(wait) if wait <= MAX_RETRY_WAIT && retries < MAX_RETRIES => {
                    retries += 1;
                    log(format!(
                        "Cert Spotter: rate limited, retrying page {page} in {}s",
                        wait.as_secs()
                    ));
                    tokio::time::sleep(wait).await;
                    continue;
                }
                _ if !sub_domains.is_empty() => {
                    log(format!(
                        "Cert Spotter: rate limited on page {page}, keeping {} subdomains found so far",
                        sub_domains.len()
                    ));
                    break;
                }
                _ => {
                    return Err(format!(
                        "Cert Spotter returned HTTP {} (rate limited, try again later)",
                        res.status()
                    ));
                }
            },
            Ok(res) => return Err(format!("Cert Spotter returned HTTP {}", res.status())),
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
        tokio::time::sleep(request_delay).await;
    }

    Ok(sub_domains)
}

fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    response
        .headers()
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn page(id: &str, name: &str) -> serde_json::Value {
        serde_json::json!([{ "id": id, "dns_names": [name] }])
    }

    async fn mount_first_page(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/v1/issuances"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page("1", "a.example.com")))
            .up_to_n_times(1)
            .with_priority(2)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn keeps_collected_subdomains_when_rate_limited_on_later_page() {
        // given
        let server = MockServer::start().await;
        mount_first_page(&server).await;
        Mock::given(method("GET"))
            .and(query_param("after", "1"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "3600"))
            .with_priority(1)
            .mount(&server)
            .await;

        // when
        let result = fetch_subdomains(&server.uri(), "example.com", Duration::ZERO, |_| {}).await;

        // then
        assert_eq!(result, Ok(HashSet::from(["a.example.com".to_string()])));
    }

    #[tokio::test]
    async fn retries_after_short_retry_after_and_continues_paginating() {
        // given
        let server = MockServer::start().await;
        mount_first_page(&server).await;
        Mock::given(method("GET"))
            .and(query_param("after", "1"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("after", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page("2", "b.example.com")))
            .up_to_n_times(1)
            .with_priority(3)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("after", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .with_priority(1)
            .mount(&server)
            .await;

        // when
        let result = fetch_subdomains(&server.uri(), "example.com", Duration::ZERO, |_| {}).await;

        // then
        assert_eq!(
            result,
            Ok(HashSet::from([
                "a.example.com".to_string(),
                "b.example.com".to_string()
            ]))
        );
    }

    #[tokio::test]
    async fn fails_when_rate_limited_before_anything_was_collected() {
        // given
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "3600"))
            .mount(&server)
            .await;

        // when
        let result = fetch_subdomains(&server.uri(), "example.com", Duration::ZERO, |_| {}).await;

        // then
        assert!(result.unwrap_err().contains("429"));
    }
}
