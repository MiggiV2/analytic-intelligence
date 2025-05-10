# Analytic Intelligence

A stealthy, server-friendly HTTPS scanner written in Rust that discovers subdomains through certificate transparency logs (crt.sh), resolves their IP addresses, and verifies website availability.

## Features

- **Subdomain Discovery**: Leverages crt.sh (Certificate Transparency logs) to find subdomains of target domains
- **IP Resolution**: Maps discovered subdomains to their hosting IP addresses
- **Website Status Checking**: Verifies availability and HTTP status of discovered websites
- **Low Detection Profile**: Implements techniques to avoid being detected as a scanning tool
- **Server-Friendly Design**: Uses rate limiting and considerate scanning techniques to minimize impact on target servers
- **Comprehensive Reporting**: Generates clear reports showing the relationships between domains, IPs, and availability

## Installation

### Prerequisites

- Rust and Cargo (latest stable version)
- OpenSSL development libraries

### From Source

```bash
# Clone the repository
git clone https://code.mymiggi.de/Miggi/analytic-intelligence.git
cd analytic-intelligence

# Build the project
cargo build --release

# The binary will be available at target/release/analytic-intelligence
```

### Using Cargo

```bash
cargo install --git https://code.mymiggi.de/Miggi/analytic-intelligence.git
```

## Usage

### Basic Usage

```bash
# Scan a domain
analytic-intelligence example.com
```

## How It Works

### Subdomain Discovery
Analytic Intelligence queries certificate transparency logs via crt.sh to discover subdomains. This method is passive and doesn't require sending traffic to the target domain, making it highly stealthy and efficient.

### IP Resolution
The tool performs DNS lookups on discovered subdomains to determine their hosting IP addresses. The resolver is configured to use multiple DNS providers and implements caching to reduce lookup volume.

### Availability Checking
For each discovered subdomain, the tool sends carefully crafted HTTP/HTTPS requests to check availability. These requests:
- Use common used user agent
- Implement exponential backoff between requests

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request to our repository at https://code.mymiggi.de/Miggi/analytic-intelligence.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---
Last updated: 2025-05-10