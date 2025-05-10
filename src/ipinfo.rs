use reqwest::Error;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct IpInfo {
    pub org: String,
    pub country: String,
    pub city: String,
}
pub fn get_ip_info(ip: &String) -> Result<IpInfo, Error> {
    let client = reqwest::blocking::Client::new();
    let url = format!("https://ipinfo.io/{}", ip);
    let response = client.get(&url).send()?;
    Ok(response.json::<IpInfo>()?)
}
