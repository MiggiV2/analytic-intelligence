mod crt;
mod ip_helper;
mod status;

use std::collections::{HashMap, HashSet};
use std::env;
use std::net::IpAddr;
use dns_lookup::lookup_host;
use serde::Deserialize;
use crate::crt::get_subdomains;
use crate::ip_helper::is_local_ip;
use crate::status::check_web_status;

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
            servers.entry(ip.to_string()).or_insert_with(Vec::new).push(domain_name);
        }
    }
    servers
}
