use std::time::Duration;

use reqwest::Client;
use reqwest::header::{HeaderMap, SET_COOKIE};

static CHROME_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
// Source: https://www.useragents.me/#latest-windows-desktop-useragents

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Security headers that should be present on a well-configured HTTPS site.
/// Order: most important first.
const SECURITY_HEADERS: [&str; 5] = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
];

pub struct SecurityReport {
    pub present: usize,
    pub total: usize,
}

pub struct Status {
    pub online: bool,
    pub title: Option<String>,
    /// Technologies detected from response headers and cookies
    pub tech: Vec<String>,
    /// Security header analysis; None when the server did not respond at all
    pub security: Option<SecurityReport>,
}

pub async fn check_web_status(domain: &str) -> Status {
    let url = format!("https://{domain}");

    let response = Client::new()
        .get(&url)
        .timeout(REQUEST_TIMEOUT)
        .header("User-Agent", CHROME_USER_AGENT)
        .send()
        .await;

    match response {
        Ok(response) => handle_response(response).await,
        Err(error) => Status {
            online: false,
            title: Some(error.to_string()),
            tech: Vec::new(),
            security: None,
        },
    }
}

async fn handle_response(response: reqwest::Response) -> Status {
    let status_code = response.status();
    let headers = response.headers().clone();

    let (online, title) = if status_code.is_success() {
        if let Ok(text) = response.text().await
            && let Some(title) = extract_html_title(text)
        {
            (true, Some(title))
        } else {
            (true, None)
        }
    } else if status_code.is_client_error() {
        (false, Some(format!("Client error: {status_code}")))
    } else if status_code.is_server_error() {
        (false, Some(format!("Server error: {status_code}")))
    } else {
        (false, Some(status_code.to_string()))
    };

    Status {
        online,
        title,
        tech: detect_tech(&headers),
        security: Some(analyze_security_headers(&headers)),
    }
}

/// Counts which of the known security headers are present in the response
fn analyze_security_headers(headers: &HeaderMap) -> SecurityReport {
    let present = SECURITY_HEADERS
        .iter()
        .filter(|name| headers.contains_key(**name))
        .count();
    SecurityReport {
        present,
        total: SECURITY_HEADERS.len(),
    }
}

/// Detects common technologies from headers (Server, X-Powered-By, ...) and
/// session cookie names. Best effort: only hints, no fingerprinting.
fn detect_tech(headers: &HeaderMap) -> Vec<String> {
    let mut tech = Vec::new();

    if let Some(server) = header_value(headers, "server") {
        match server.to_lowercase().as_str() {
            "microsoft-iis" => add_tech(&mut tech, "IIS"),
            "apache-coyote" => add_tech(&mut tech, "Tomcat"),
            "cloudflare" => add_tech(&mut tech, "Cloudflare"),
            _ => add_tech(&mut tech, &server),
        }
    }

    if let Some(powered_by) = header_value(headers, "x-powered-by") {
        match powered_by.to_lowercase() {
            s if s.starts_with("php") => add_tech(&mut tech, "PHP"),
            s if s.starts_with("asp.net") => add_tech(&mut tech, "ASP.NET"),
            s if s.starts_with("express") => add_tech(&mut tech, "Express"),
            s if s.starts_with("servlet") || s.starts_with("jsf") => add_tech(&mut tech, "Java"),
            _ => add_tech(&mut tech, &powered_by),
        }
    }

    if headers.contains_key("x-aspnet-version") || headers.contains_key("x-aspnetmvc-version") {
        add_tech(&mut tech, "ASP.NET");
    }
    if let Some(generator) = header_value(headers, "x-generator") {
        add_tech(&mut tech, &generator);
    }
    if let Some(redirect_by) = header_value(headers, "x-redirect-by") {
        add_tech(&mut tech, &redirect_by);
    }

    for cookie in headers.get_all(SET_COOKIE) {
        if let Some(name) = cookie.to_str().ok().and_then(|c| c.split('=').next()) {
            match name.to_lowercase().as_str() {
                "phpsessid" => add_tech(&mut tech, "PHP"),
                "jsessionid" => add_tech(&mut tech, "Java"),
                "asp.net_sessionid" | "asp.netcore" | ".aspxauth" => add_tech(&mut tech, "ASP.NET"),
                "laravel_session" | "laravel_token" => add_tech(&mut tech, "Laravel"),
                "csrftoken" => add_tech(&mut tech, "Django"),
                "ci_session" => add_tech(&mut tech, "CodeIgniter"),
                _ => {}
            }
        }
    }

    tech
}

/// Returns the header value stripped of version and build details,
/// e.g. "nginx/1.25.3" -> "nginx", "PHP/7.4.3" -> "PHP"
fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let value = headers.get(name)?.to_str().ok()?;
    let token = value.split(&['/', ' ']).next()?.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn add_tech(tech: &mut Vec<String>, name: &str) {
    if !tech.iter().any(|t| t.eq_ignore_ascii_case(name)) {
        tech.push(name.to_string());
    }
}

fn extract_html_title(html: String) -> Option<String> {
    // Case insensitive search for the title tag
    let html_lowercase = html.to_lowercase();

    // Find the start of the title tag
    let title_start_idx = html_lowercase.find("<title>")?;
    // Add the length of "<title>" to get to the start of the content
    let content_start_idx = title_start_idx + 7;

    // Find the end of the title tag
    let title_end_idx = html_lowercase[content_start_idx..].find("</title>")?;
    // Calculate the absolute index of the end of the title content
    let content_end_idx = content_start_idx + title_end_idx;

    // Extract the title content from the original HTML (preserving case)
    if content_end_idx > content_start_idx {
        Some(html[content_start_idx..content_end_idx].trim().to_string())
    } else {
        None
    }
}
