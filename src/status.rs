use std::time::Duration;

static CHROME_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36";
// Source: https://www.useragents.me/#latest-windows-desktop-useragents

pub fn check_web_status(domain: &String) -> String {
    let url = format!("https://{}", domain);
    let client = reqwest::blocking::Client::new();
    // println!("Checking {}", url);

    let response = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .header("User-Agent", CHROME_USER_AGENT)
        .send();

    if let Ok(response) = response {
        if response.status().is_success() {
            if let Ok(text) = response.text() {
                let title = extract_html_title(text);
                if let Some(title) = title {
                    return format!("✅\n↪️ {}", title);
                }
            }
            return String::from("✅");
        }
        return response.status().to_string();
    }
    String::from("❌")
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
