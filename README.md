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
- **Reverse DNS**: Resolves the PTR record for every hosting IP (e.g. CDN edge or hosting server hostnames)
- **TLS Certificate Analysis**: Reads the served certificate per host - issuer, days until expiry and
  self-signed detection (skips chain validation on purpose: an invalid certificate is a finding, not an error)
- **Security Header Check**: Scores how many of five recommended security headers are set
  (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- **Tech Detection**: Identifies common technologies from response headers and session cookie names
  (nginx, Apache, IIS, PHP, ASP.NET, Next.js, Cloudflare, ...)
- **Feature Toggles**: Every check can be switched on/off in the TUI while the scan is running (keys `1`-`4`)
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
 q: quit  -  j/k: scroll  -  f: follow    toggle: 1:sec-hdrs 2:tls 3:tech 4:ptr
```

With all features enabled the results table also shows a PTR column (reverse DNS per IP),
a TLS column (issuer abbreviation + days until expiry, `SS` = self-signed, `expired`),
a Tech column (detected technologies) and a Sec column (present security headers, e.g. `3/5`).

### Keybindings

| Key             | Action                    |
| --------------- | ------------------------- |
| `q` / `Esc`     | Quit                      |
| `j` / `Down`    | Scroll down               |
| `k` / `Up`      | Scroll up                 |
| `g` / `Home`    | Jump to the first row     |
| `G` / `End`/`f` | Jump to the last row/follow |
| `1`             | Toggle security header column |
| `2`             | Toggle TLS certificate analysis |
| `3`             | Toggle tech detection column |
| `4`             | Toggle reverse DNS column |

Toggles take effect while the scan is running: turning off TLS analysis (`2`) or reverse DNS (`4`)
skips their network requests from that point on. Security headers and tech detection piggyback on
the HTTP responses the scan fetches anyway, so their toggles only hide the corresponding columns.

## How It Works

### Subdomain Discovery

Analytic Intelligence queries certificate transparency logs to discover subdomains. crt.sh is used as the primary
source; if it is unavailable (which happens regularly), the tool automatically falls back to
[SSLMate Cert Spotter](https://sslmate.com/certspotter) (keyless free tier, indexes 40+ CT logs, subdomains of any
depth via `include_subdomains=true`, paginated via `after=<id>` with a conservative rate of one request per second).
On HTTP 429 it waits for a short `Retry-After` (≤ 30 s, up to 3 retries); if the limit persists, the subdomains
collected from the pages fetched so far are kept.
Both methods are passive and don't require sending traffic to the target domain, making them highly stealthy
and efficient.

### IP Resolution

The tool performs DNS lookups on discovered subdomains to determine their hosting IP addresses. The resolver is
configured to use multiple DNS providers and implements caching to reduce lookup volume. For every unique hosting
IP a reverse DNS (PTR) lookup is performed, which often reveals the hosting provider's server hostname.

### Availability Checking

For each discovered subdomain, the tool sends carefully crafted HTTP/HTTPS requests to check availability. These
requests:

- Use common used user agent
- Target the same IP strictly one after another, with a randomized delay of 0.5 to 1.8 seconds between requests,
  so rate-based firewall rules do not flag the scan
- Check different IPs in parallel, capped at 10 IPs at a time

Each response is additionally analyzed for security headers and technology hints, and every resolved host gets a
TLS probe that reads the served certificate (issuer, expiry, self-signed) without validating the chain.

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