pub fn check_web_status(domain: &String) -> String {
    let url = format!("https://{}", domain);
    let client = reqwest::blocking::Client::new();
    // println!("Checking {}", url);

    let response = client.head(&url).send();
    if response.is_err() {
        return String::from("?");
    }

    let response= response.unwrap();
    // println!("Status: {}", response.status());
    if response.status().is_success() {
        return String::from( "✅");
    }
    response.status().to_string()
}