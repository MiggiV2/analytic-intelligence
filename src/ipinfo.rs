use serde::Deserialize;

#[derive(Deserialize)]
pub struct IpInfo {
    pub org: String,
    pub country: String,
    pub city: String,
}

pub async fn get_ip_info(ip: &str) -> Result<IpInfo, String> {
    let url = format!("https://ipinfo.io/{ip}");
    let response = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("ipinfo.io request failed: {e}"))?;
    response
        .json::<IpInfo>()
        .await
        .map_err(|e| format!("ipinfo.io response could not be parsed: {e}"))
}
