# Analytic Intelligence

A stealthy, server-friendly HTTPS scanner written in Rust that discovers subdomains through certificate transparency
logs (crt.sh, with SSLMate Cert Spotter as fallback), resolves their IP addresses, and verifies website availability -
presented in a live-updating terminal UI.

## Features

- **Subdomain Discovery**: Leverages certificate transparency logs to find subdomains of target domains
  (crt.sh, falling back to SSLMate Cert Spotter when crt.sh is unavailable)
- **Live TUI**: Terminal user interface built with ratatui - results stream in while the scan is running
- **IP Resolution**: Maps discovered subdomains to their hosting IP addresses
- **Website Status Checking**: Verifies availability and HTTP status of discovered websites
- **Low Detection Profile**: Implements techniques to avoid being detected as a scanning tool
- **Server-Friendly Design**: Uses rate limiting and considerate scanning techniques to minimize impact on target
  servers
- **Comprehensive Reporting**: Generates clear reports showing the relationships between domains, IPs, and availability

## Installation

### Download from release page

You can download the latest compiled version for Linux_AMD64 and Windows_AMD64 from the release page.  
-> https://code.mymiggi.de/Miggi/analytic-intelligence/releases

### Prerequisites

- Rust and Cargo (latest stable version)

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

```bash
# Scan a domain
analytic-intelligence example.com
```

The terminal switches into a full-screen TUI that shows the scan progress live:

```
┌ Scan ──────────────────────────────────────────────────────────────────────┐
│ Analytic Intelligence  mymiggi.de                                           │
│ Phase: Checking websites  -  30 subdomains via Cert Spotter                 │
│ Mail server: 5 mail.tutanota.de.                                            │
└─────────────────────────────────────────────────────────────────────────────┘
███████████████████████████████████ checked 23 / 30 ██████████████████████████
┌ Results (up 19 - down 4 - skipped 0) ────────────────────────────────────────┐
│ State   Domain                    IP              Organization / Location   │
│ UP      mymiggi.de               104.21.20.30    AS13335 Cloudflare, Inc.    │
│ DOWN    traefik-hetzner.mymigg…  78.46.191.125  AS24940 Hetzner Online GmbH │
│ ...                                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
 q: quit  -  j/k or up/down: scroll  -  f: follow
```

### Keybindings

| Key             | Action                    |
| --------------- | ------------------------- |
| `q` / `Esc`     | Quit                      |
| `j` / `Down`    | Scroll down               |
| `k` / `Up`      | Scroll up                 |
| `g` / `Home`    | Jump to the first row     |
| `G` / `End`/`f` | Jump to the last row/follow |

## How It Works

### Subdomain Discovery

Analytic Intelligence queries certificate transparency logs to discover subdomains. crt.sh is used as the primary
source; if it is unavailable (which happens regularly), the tool automatically falls back to
[SSLMate Cert Spotter](https://sslmate.com/certspotter) (keyless free tier, indexes 40+ CT logs, subdomains of any
depth via `include_subdomains=true`, paginated via `after=<id>` with a conservative rate of one request per second).
Both methods are passive and don't require sending traffic to the target domain, making them highly stealthy
and efficient.

### IP Resolution

The tool performs DNS lookups on discovered subdomains to determine their hosting IP addresses. The resolver is
configured to use multiple DNS providers and implements caching to reduce lookup volume.

### Availability Checking

For each discovered subdomain, the tool sends carefully crafted HTTP/HTTPS requests to check availability. These
requests:

- Use common used user agent
- Target the same IP strictly one after another, with a randomized delay of 0.5 to 1.8 seconds between requests,
  so rate-based firewall rules do not flag the scan
- Check different IPs in parallel, capped at 10 IPs at a time

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request to our repository
at https://code.mymiggi.de/Miggi/analytic-intelligence.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.