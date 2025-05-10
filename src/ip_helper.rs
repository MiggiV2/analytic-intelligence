use std::net::IpAddr;

// Helper function to check if an IP is a local/private address
pub fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback() ||
                ipv4.is_unspecified() ||
                // Private IPv4 ranges
                ipv4.octets()[0] == 10 || // 10.0.0.0/8
                (ipv4.octets()[0] == 172 && (ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31)) || // 172.16.0.0/12
                (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168) || // 192.168.0.0/16
                // Link-local addresses
                (ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254) // 169.254.0.0/16
        },
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() ||
                ipv6.is_unspecified() ||
                // ULA (Unique Local Address)
                (ipv6.segments()[0] & 0xfe00) == 0xfc00 ||
                // Link-local addresses
                (ipv6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}