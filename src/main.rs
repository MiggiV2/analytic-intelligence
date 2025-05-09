use std::collections::{HashMap, HashSet};
use std::env;
use dns_lookup::lookup_host;
use serde::Deserialize;

#[derive(Deserialize)]
struct Cert {
    common_name:String,
    name_value: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2{
        panic!("Please start the program with an DOMAIN as argument");
    }

    // ToDo: Add unknown 2nd level domains in loop
    let sub_domains = get_subdomains(args);
    let servers = build_server_map(sub_domains);

    for (ip, domains) in servers {
        println!("IP: {}", ip);
        for domain in domains {
            println!("- {} -> {}", domain, check_web_status(&domain));
        }
        println!();
    }
}

fn check_web_status(domain: &String) -> String {
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

fn build_server_map(sub_domains: HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut servers = HashMap::new();
    for domain_name in sub_domains {
        let ips = lookup_host(&domain_name);
        if ips.is_err() {
            continue;
        }

        let ip = ips.unwrap().first().unwrap().to_string();
        servers.entry(ip).or_insert_with(Vec::new).push(domain_name);
    }
    servers
}

fn get_subdomains(args: Vec<String>) -> HashSet<String> {
    let url = format!("https://crt.sh/json?q={}&exclude=expired", args.get(1).unwrap());
    let body = reqwest::blocking::get(url)
        .unwrap()
        .json::<Vec<Cert>>();

    let mut sub_domains = HashSet::new();

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
