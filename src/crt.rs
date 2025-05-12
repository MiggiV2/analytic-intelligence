use crate::Cert;
use std::collections::HashSet;

pub fn get_subdomains(domain: &String) -> HashSet<String> {
    let url = format!("https://crt.sh/json?q={}&exclude=expired", domain);
    let body = reqwest::blocking::get(url).unwrap().json::<Vec<Cert>>();

    let mut sub_domains = HashSet::new();
    
    if let Err(err) = body {
        panic!("crt.sh request failed -> {}\nStopping programm now...", err)
    }

    for cert in body.unwrap() {
        if !cert.common_name.is_empty() {
            sub_domains.insert(cert.common_name);
        }
        if !cert.name_value.is_empty() {
            if cert.name_value.contains("\n") {
                for name in cert.name_value.split("\n") {
                    if name.starts_with("*.") {
                        continue;
                    }
                    sub_domains.insert(name.trim().to_string());
                }
            } else {
                sub_domains.insert(cert.name_value);
            }
        }
    }
    sub_domains
}
