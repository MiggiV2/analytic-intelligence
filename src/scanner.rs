use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rand::Rng;
use tokio::sync::{Semaphore, mpsc};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

use crate::certspotter;
use crate::crt;
use crate::ip_helper::is_local_ip;
use crate::ipinfo::{IpInfo, get_ip_info};
use crate::ptr;
use crate::status::{Status, check_web_status};
use crate::tls::{self, TlsInfo};

// Be considerate: modest concurrency for DNS, HTTP and ipinfo.io requests
const DNS_CONCURRENCY: usize = 25;
/// Maximum number of IPs whose domains are checked in parallel
const HTTP_CONCURRENCY: usize = 10;
const IPINFO_CONCURRENCY: usize = 5;
// Randomized delay between HTTP requests to the same IP,
// so rate-based firewall rules do not flag the scan
const HTTP_JITTER_MIN_MS: u64 = 500;
const HTTP_JITTER_MAX_MS: u64 = 1800;

#[derive(Clone, Copy, PartialEq)]
pub enum Phase {
    MailServer,
    Discovery,
    Resolving,
    ReverseDns,
    Checking,
    Done,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Phase::MailServer => "Looking up mail server",
            Phase::Discovery => "Discovering subdomains",
            Phase::Resolving => "Resolving IP addresses",
            Phase::ReverseDns => "Resolving reverse DNS",
            Phase::Checking => "Checking websites",
            Phase::Done => "Done",
        };
        write!(f, "{name}")
    }
}

/// Which checks the scan performs. Shared between the TUI (writes) and the
/// scanner (reads), so the user can toggle features while a scan is running.
/// Toggling off `tls_cert` / `reverse_dns` skips their network requests,
/// `security_headers` / `tech` are extracted from responses the scan fetches
/// anyway and only hide the corresponding columns.
#[derive(Clone, Copy)]
pub struct ScanOptions {
    pub security_headers: bool,
    pub tls_cert: bool,
    pub tech: bool,
    pub reverse_dns: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            security_headers: true,
            tls_cert: true,
            tech: true,
            reverse_dns: true,
        }
    }
}

pub type SharedOptions = Arc<RwLock<ScanOptions>>;

fn current_options(options: &SharedOptions) -> ScanOptions {
    *options.read().unwrap_or_else(|e| e.into_inner())
}

#[derive(Clone, Copy)]
pub enum Source {
    CrtSh,
    CertSpotter,
}

impl Source {
    pub fn from_name(name: &str) -> Option<Source> {
        [Source::CrtSh, Source::CertSpotter]
            .into_iter()
            .find(|source| source.to_string() == name)
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Source::CrtSh => "crt.sh",
            Source::CertSpotter => "Cert Spotter",
        };
        write!(f, "{name}")
    }
}

pub enum ScanEvent {
    Phase(Phase),
    Log(String),
    MailServer(String),
    /// Total number of discovered subdomains and the source that provided them
    Discovery {
        count: usize,
        source: Source,
    },
    /// A row for the table: domain got resolved to an IP address
    HostResolved {
        domain: String,
        ip: String,
    },
    /// ipinfo.io data for an IP address
    IpInfo {
        ip: String,
        info: IpInfo,
    },
    /// HTTP check result for a domain (counts towards progress)
    HostChecked {
        domain: String,
        status: Status,
    },
    /// TLS certificate analysis for a domain (None when the probe failed)
    TlsChecked {
        domain: String,
        info: Option<TlsInfo>,
    },
    /// Reverse DNS result for an IP address (None when no PTR record exists)
    PtrRecord {
        ip: String,
        ptr: Option<String>,
    },
    /// Domain will not be checked (e.g. resolves to a local IP, counts towards progress)
    HostSkipped {
        domain: String,
        reason: String,
    },
    SourceError {
        source: Source,
        error: String,
    },
    Finished,
}

pub async fn run_scan(
    domain: String,
    options: SharedOptions,
    tx: mpsc::UnboundedSender<ScanEvent>,
) {
    let _ = tx.send(ScanEvent::Phase(Phase::MailServer));

    let resolver = match create_resolver().await {
        Ok(resolver) => ResolverGuard::new(resolver),
        Err(err) => {
            let _ = tx.send(ScanEvent::Log(format!("DNS resolver failed: {err}")));
            let _ = tx.send(ScanEvent::Finished);
            return;
        }
    };

    lookup_mail_server(&domain, &resolver, &tx).await;
    let _ = tx.send(ScanEvent::Phase(Phase::Discovery));

    let (sub_domains, source) = discover_subdomains(&domain, &tx).await;
    let _ = tx.send(ScanEvent::Discovery {
        count: sub_domains.len(),
        source,
    });

    let _ = tx.send(ScanEvent::Phase(Phase::Resolving));
    let hosts = resolve_hosts(sub_domains, &resolver.get(), &tx).await;

    if current_options(&options).reverse_dns {
        let _ = tx.send(ScanEvent::Phase(Phase::ReverseDns));
        lookup_ptr_records(&hosts, &resolver.get(), &tx).await;
    }

    let _ = tx.send(ScanEvent::Phase(Phase::Checking));
    check_hosts(&hosts, &options, &tx).await;

    let _ = tx.send(ScanEvent::Phase(Phase::Done));
    let _ = tx.send(ScanEvent::Finished);
}

/// Owns the DNS resolver and makes sure its final drop never happens on a
/// tokio worker thread: the resolver internally owns a tokio runtime, and
/// dropping a runtime from an async context panics. This also covers task
/// cancellation (e.g. the user quits while the scan is still running).
struct ResolverGuard {
    resolver: Option<Arc<Resolver>>,
}

impl ResolverGuard {
    fn new(resolver: Resolver) -> Self {
        Self {
            resolver: Some(Arc::new(resolver)),
        }
    }

    fn get(&self) -> Arc<Resolver> {
        Arc::clone(self.resolver.as_ref().expect("resolver already dropped"))
    }
}

impl Drop for ResolverGuard {
    fn drop(&mut self) {
        if let Some(resolver) = self.resolver.take()
            && Arc::strong_count(&resolver) == 1
        {
            std::thread::spawn(move || drop(resolver));
        }
    }
}

async fn create_resolver() -> Result<Resolver, String> {
    tokio::task::spawn_blocking(|| {
        Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn lookup_mail_server(
    domain: &str,
    resolver: &ResolverGuard,
    tx: &mpsc::UnboundedSender<ScanEvent>,
) {
    let resolver = resolver.get();
    let domain = domain.to_string();
    let result = tokio::task::spawn_blocking(move || {
        resolver
            .mx_lookup(&domain)
            .map(|res| res.iter().next().map(|mx| mx.to_string()))
    })
    .await;

    if let Ok(Ok(Some(mail))) = result {
        let _ = tx.send(ScanEvent::MailServer(mail));
    }
}

/// Queries crt.sh first and falls back to Cert Spotter if crt.sh is unavailable
async fn discover_subdomains(
    domain: &str,
    tx: &mpsc::UnboundedSender<ScanEvent>,
) -> (HashSet<String>, Source) {
    match crt::get_subdomains(domain).await {
        Ok(sub_domains) => (sub_domains, Source::CrtSh),
        Err(error) => {
            let _ = tx.send(ScanEvent::SourceError {
                source: Source::CrtSh,
                error,
            });
            let log_tx = tx.clone();
            let log = move |msg: String| {
                let _ = log_tx.send(ScanEvent::Log(msg));
            };
            match certspotter::get_subdomains(domain, log).await {
                Ok(sub_domains) => (sub_domains, Source::CertSpotter),
                Err(error) => {
                    let _ = tx.send(ScanEvent::SourceError {
                        source: Source::CertSpotter,
                        error,
                    });
                    (HashSet::new(), Source::CrtSh)
                }
            }
        }
    }
}

/// Resolves every subdomain and emits `HostResolved` / `HostSkipped` events.
/// Returns the resolved (ip, domain) pairs; local addresses are skipped,
/// domains that fail to resolve are kept with the ip "unknown" and still checked.
async fn resolve_hosts(
    sub_domains: HashSet<String>,
    resolver: &Arc<Resolver>,
    tx: &mpsc::UnboundedSender<ScanEvent>,
) -> Vec<(String, String)> {
    let semaphore = Arc::new(Semaphore::new(DNS_CONCURRENCY));
    let mut tasks = Vec::with_capacity(sub_domains.len());

    for domain in sub_domains {
        let semaphore = Arc::clone(&semaphore);
        let resolver = Arc::clone(resolver);
        let tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            let permit = semaphore.acquire_owned().await;
            let lookup_domain = domain.clone();
            let lookup = tokio::task::spawn_blocking(move || {
                let _ = permit;
                resolver.lookup_ip(&lookup_domain)
            })
            .await;

            match lookup {
                Ok(Ok(ips)) => match ips.iter().next() {
                    Some(ip) if is_local_ip(&ip) => {
                        let _ = tx.send(ScanEvent::HostSkipped {
                            domain,
                            reason: format!("local IP address {ip}"),
                        });
                        None
                    }
                    Some(ip) => {
                        let _ = tx.send(ScanEvent::HostResolved {
                            domain: domain.clone(),
                            ip: ip.to_string(),
                        });
                        Some((ip.to_string(), domain))
                    }
                    None => {
                        let _ = tx.send(ScanEvent::HostSkipped {
                            domain,
                            reason: "no IP address found".to_string(),
                        });
                        None
                    }
                },
                Ok(Err(err)) => dns_failed(tx, domain, &err.to_string()),
                Err(err) => dns_failed(tx, domain, &err.to_string()),
            }
        }));
    }

    let mut hosts = Vec::with_capacity(tasks.len());
    for task in tasks {
        if let Ok(Some(host)) = task.await {
            hosts.push(host);
        }
    }
    hosts
}

/// Keeps the original behavior: domains that fail to resolve are grouped
/// under the pseudo IP "unknown" and still get a status check
fn dns_failed(
    tx: mpsc::UnboundedSender<ScanEvent>,
    domain: String,
    error: &str,
) -> Option<(String, String)> {
    let _ = tx.send(ScanEvent::Log(format!(
        "Failed to resolve domain {domain}: {error}"
    )));
    let _ = tx.send(ScanEvent::HostResolved {
        domain: domain.clone(),
        ip: String::from("unknown"),
    });
    Some((String::from("unknown"), domain))
}

/// Checks all hosts: ipinfo.io per unique IP and HTTPS status per domain.
/// Domains on the same IP are checked sequentially with a randomized delay
/// between requests, so per-IP traffic does not look like a scanner.
/// When enabled, each resolved host additionally gets a TLS probe.
async fn check_hosts(
    hosts: &[(String, String)],
    options: &SharedOptions,
    tx: &mpsc::UnboundedSender<ScanEvent>,
) {
    fetch_ip_info(hosts, tx).await;

    let per_ip = group_by_ip(hosts);
    let semaphore = Arc::new(Semaphore::new(HTTP_CONCURRENCY));
    let mut tasks = Vec::with_capacity(per_ip.len());

    for (ip, domains) in per_ip {
        let semaphore = Arc::clone(&semaphore);
        let tx = tx.clone();
        let options = Arc::clone(options);
        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            for (index, domain) in domains.iter().enumerate() {
                if index > 0 {
                    tokio::time::sleep(jittered_delay()).await;
                }
                let scan_options = current_options(&options);
                let status = check_web_status(domain).await;
                let _ = tx.send(ScanEvent::HostChecked {
                    domain: domain.clone(),
                    status,
                });
                // The TLS probe targets the same IP as the request before it
                // and reads the certificate the server sends anyway
                if scan_options.tls_cert && ip != "unknown" {
                    let info = tls::check_tls(domain).await.ok();
                    let _ = tx.send(ScanEvent::TlsChecked {
                        domain: domain.clone(),
                        info,
                    });
                }
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
}

/// Reverse DNS for every unique IP the scan resolved, so the table can show
/// the hostname behind an address (e.g. CDN edge or hosting server).
async fn lookup_ptr_records(
    hosts: &[(String, String)],
    resolver: &Arc<Resolver>,
    tx: &mpsc::UnboundedSender<ScanEvent>,
) {
    let unique_ips: HashSet<&str> = hosts
        .iter()
        .map(|(ip, _)| ip.as_str())
        .filter(|ip| *ip != "unknown")
        .collect();

    let semaphore = Arc::new(Semaphore::new(DNS_CONCURRENCY));
    let mut tasks = Vec::with_capacity(unique_ips.len());

    for ip in unique_ips {
        let semaphore = Arc::clone(&semaphore);
        let resolver = Arc::clone(resolver);
        let tx = tx.clone();
        let ip = ip.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            let ptr = ptr::lookup_ptr(&resolver, &ip).await;
            let _ = tx.send(ScanEvent::PtrRecord { ip, ptr });
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
}

fn group_by_ip(hosts: &[(String, String)]) -> Vec<(String, Vec<String>)> {
    let mut per_ip: Vec<(String, Vec<String>)> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();

    for (ip, domain) in hosts {
        let next = per_ip.len();
        let position = *index.entry(ip.as_str()).or_insert(next);
        if position == next {
            per_ip.push((ip.clone(), Vec::new()));
        }
        per_ip[position].1.push(domain.clone());
    }
    per_ip
}

fn jittered_delay() -> Duration {
    let millis = rand::rng().random_range(HTTP_JITTER_MIN_MS..=HTTP_JITTER_MAX_MS);
    Duration::from_millis(millis)
}

async fn fetch_ip_info(hosts: &[(String, String)], tx: &mpsc::UnboundedSender<ScanEvent>) {
    let semaphore = Arc::new(Semaphore::new(IPINFO_CONCURRENCY));
    let unique_ips: HashSet<&str> = hosts
        .iter()
        .map(|(ip, _)| ip.as_str())
        .filter(|ip| *ip != "unknown")
        .collect();
    let mut tasks = Vec::with_capacity(unique_ips.len());

    for ip in unique_ips {
        let semaphore = Arc::clone(&semaphore);
        let tx = tx.clone();
        let ip = ip.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            match get_ip_info(&ip).await {
                Ok(info) => {
                    let _ = tx.send(ScanEvent::IpInfo { ip, info });
                }
                Err(err) => {
                    let _ = tx.send(ScanEvent::Log(format!("ipinfo.io failed for {ip}: {err}")));
                }
            }
        }));
    }

    for task in tasks {
        let _ = task.await;
    }
}
