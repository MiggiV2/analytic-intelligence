use reqwest::blocking::{Client, Response};
use std::time::Duration;

static CHROME_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
// Source: https://www.useragents.me/#latest-windows-desktop-useragents

pub struct Status {
    pub online: bool,
    pub title: Option<String>,
}

impl Status {
    pub fn new(online: bool) -> Status {
        Self {
            online,
            title: None,
        }
    }

    pub fn online_with_title(title: String) -> Status {
        Self {
            online: true,
            title: Some(title),
        }
    }

    pub fn offline_with_title(title: String) -> Status {
        Self {
            online: false,
            title: Some(title),
        }
    }
}

// toDo: Async
pub fn check_web_status(domain: &str) -> Status {
    let url = format!("https://{}", domain);
    let client = Client::new();

    let response = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .header("User-Agent", CHROME_USER_AGENT)
        .send();

    match response {
        Ok(response) => handle_response(response),
        Err(error) => Status::offline_with_title(error.to_string()),
    }
}

fn handle_response(response: Response) -> Status {
    let status_code = response.status();

    if status_code.is_success() {
        if let Ok(text) = response.text() {
            if let Some(title) = extract_html_title(text) {
                return Status::online_with_title(title);
            }
        }
        Status::new(true)
    } else if status_code.is_client_error() {
        Status::offline_with_title(format!("Client error: {}", status_code))
    } else if status_code.is_server_error() {
        Status::offline_with_title(format!("Server error: {}", status_code))
    } else {
        Status::offline_with_title(status_code.to_string())
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
