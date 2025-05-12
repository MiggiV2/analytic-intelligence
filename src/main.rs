mod crt;
mod ip_helper;
mod ipinfo;
mod status;

use crate::crt::get_subdomains;
use crate::ip_helper::is_local_ip;
use crate::ipinfo::get_ip_info;
use crate::status::check_web_status;
use std::collections::{HashMap, HashSet};
use std::env;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

fn main() {
    let domain = parse_arguments();
    let resolver = create_resolver();

    display_mail_servers(&domain, &resolver);

    let sub_domains = get_subdomains(&domain);
    let servers = build_server_map(sub_domains);

    display_server_information(servers);
}

fn parse_arguments() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Error: Please provide a domain name as argument");
        eprintln!("Usage: {} <domain>", args[0]);
        std::process::exit(1);
    }
    args[1].clone()
}

fn display_mail_servers(domain: &str, resolver: &Resolver) {
    if let Ok(res) = resolver.mx_lookup(domain) {
        if let Some(mx) = res.iter().next() {
            let mail = mx.to_string();
            println!("📧 E-Mail Server: {}\n", mail);
        }
    }
}

fn display_server_information(servers: HashMap<String, Vec<String>>) {
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
            let icon = if status.online { "✅" } else { "❌" };
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

fn create_resolver() -> Resolver {
    let resolver_config = ResolverConfig::cloudflare_tls();
    let resolver_opts = ResolverOpts::default();
    Resolver::new(resolver_config, resolver_opts).expect("Failed to create DNS resolver")
}

fn build_server_map(sub_domains: HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut servers = HashMap::new();
    let resolver = create_resolver();

    for domain_name in sub_domains {
        match resolver.lookup_ip(&domain_name) {
            Ok(ips) => {
                if let Some(ip) = ips.iter().next() {
                    if is_local_ip(&ip) {
                        println!("Skipping local IP {} for domain {}", &ip, domain_name);
                        continue;
                    }
                    servers
                        .entry(ip.to_string())
                        .or_insert_with(Vec::new)
                        .push(domain_name);
                }
            }
            Err(err) => {
                eprintln!("Failed to resolve domain {}: {}", domain_name, err);
                servers
                    .entry(String::from("unknown"))
                    .or_insert_with(Vec::new)
                    .push(domain_name);
            }
        }
    }
    servers
}
