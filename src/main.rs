mod crt;
mod ip_helper;
mod ipinfo;
mod status;

use crate::crt::get_subdomains;
use crate::ip_helper::is_local_ip;
use crate::ipinfo::get_ip_info;
use crate::status::check_web_status;
use dns_lookup::lookup_host;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env;

#[derive(Deserialize)]
struct Cert {
    common_name: String,
    name_value: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        panic!("Please start the program with an DOMAIN as argument");
    }

    // ToDo: Add unknown 2nd level domains in loop
    let sub_domains = get_subdomains(args);
    let servers = build_server_map(sub_domains);

    for (ip, domains) in servers {
        print!("IP: {} ", &ip);
        let ip_info = get_ip_info(&ip);
        match ip_info {
            Ok(info) => {
                println!("({}, {}, {})", info.org, info.country, info.city);
            }
            Err(err) => {
                println!("{}", err);
            }
        }
        for domain in domains {
            println!("- {} {}", domain, check_web_status(&domain));
        }
        println!();
    }
}

fn build_server_map(sub_domains: HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut servers = HashMap::new();
    for domain_name in sub_domains {
        let ips = lookup_host(&domain_name);
        if ips.is_err() {
            continue;
        }

        let ips = ips.unwrap();
        if let Some(ip) = ips.first() {
            // Skip local IP addresses
            if is_local_ip(ip) {
                println!("Skipping local IP {} for domain {}", ip, domain_name);
                continue;
            }
            servers
                .entry(ip.to_string())
                .or_insert_with(Vec::new)
                .push(domain_name);
        }
    }
    servers
}
