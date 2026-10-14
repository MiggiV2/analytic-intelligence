use std::net::IpAddr;
use std::sync::Arc;

use trust_dns_resolver::Resolver;

/// Reverse DNS: resolves the PTR record of an IP address, e.g. the hostname of
/// a CDN edge or the hosting provider's server. Uses the same resolver as the
/// forward lookups, so no additional infrastructure is needed.
/// Returns None when no PTR record exists.
pub async fn lookup_ptr(resolver: &Arc<Resolver>, ip: &str) -> Option<String> {
    let ip: IpAddr = ip.parse().ok()?;
    let resolver = Arc::clone(resolver);
    let lookup = tokio::task::spawn_blocking(move || resolver.reverse_lookup(ip))
        .await
        .ok()?
        .ok()?;

    lookup
        .iter()
        .next()
        .map(|ptr| ptr.to_string().trim_end_matches('.').to_string())
}
