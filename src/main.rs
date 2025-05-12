mod crt;
mod ip_helper;
mod ipinfo;
mod status;

use crate::crt::get_subdomains;
use crate::ip_helper::is_local_ip;
use crate::ipinfo::get_ip_info;
use crate::status::check_web_status;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::env;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

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

    let domain = args.get(1).unwrap();
    let resolver = Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
    if let Ok(res) = resolver.mx_lookup(domain) {
        if let Some(mx) = res.iter().next() {
            let mail = mx.to_string();
            println!("📧 E-Mail Server: {}\n", mail);
        }
    }

    // ToDo: Add unknown 2nd level domains in loop
    let sub_domains = get_subdomains(domain);
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
            let status = check_web_status(&domain);
            let icon;
            if status.online {
                icon = "✅";
            } else {
                icon = "❌";
            }
            println!("{} {}", icon, domain,);
            if let Some(title) = status.title {
                println!("↪️ {}", title);
            } else {
                println!();
            }
        }
        println!();
    }
}

fn build_server_map(sub_domains: HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut servers = HashMap::new();
    let resolver = Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
    for domain_name in sub_domains {
        let ips = resolver.lookup_ip(&domain_name);
        let mut ip_addr = String::from("unknown");

        match ips {
            Ok(ips) => {
                if let Some(ip) = ips.iter().next() {
                    // Skip local IP addresses
                    if is_local_ip(&ip) {
                        println!("Skipping local IP {} for domain {}", &ip, domain_name);
                        continue;
                    }
                    ip_addr = ip.to_string();
                }
            },
            Err(err) => {
                eprintln!("Failed to get IP {}", err);
            }
        }

        servers
            .entry(ip_addr)
            .or_insert_with(Vec::new)
            .push(domain_name);
    }
    servers
}
