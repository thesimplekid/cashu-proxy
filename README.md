# Cashu Proxy

A HTTP proxy service that requires Cashu tokens for access, enabling pay-per-request APIs and services.

## Overview

Cashu Proxy sits between clients and your HTTP services, requiring payment in the form of Cashu tokens before forwarding requests. This enables monetization of APIs and web services on a per-request basis with minimal integration effort.

## Features

- **Pay-per-request**: Require Cashu tokens for each request
- **P2PK Conditions**: Use P2PK conditions to ensure tokens can only be spent by the proxy
- **Configurable**: Easy configuration via TOML file
- **Multiple Mints**: Support for multiple Cashu mints
- **Token Expiry**: Configure token validity periods

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/cashu-proxy.git
cd cashu-proxy

# Build the project
cargo build --release

# Copy the example config
mkdir -p ~/.cashu-proxy
cp config.toml.example ~/.cashu-proxy/config.toml

# Edit the config file with your settings
nano ~/.cashu-proxy/config.toml
```

## Configuration

Edit the `~/.cashu-proxy/config.toml` file to configure the proxy:

```toml
# Address to listen on
listen_addr = "0.0.0.0:6188"

# Upstream server to proxy to
upstream_addr = "127.0.0.1:8085"

# List of mints to use
mints = [
  "https://nofees.testnut.cashu.space"
]

# Cost in satoshis per request
cost = 1

# Minimum lock time in seconds (how long a token is valid after payment)
min_lock_time = 300

# Secret key for P2PK conditions (REQUIRED)
secret_key = "your-secret-key-here"

# Optional custom database path
# db_path = "/path/to/custom/database.redb"
```

### Configuration Options

- `listen_addr`: The address and port the proxy will listen on
- `upstream_addr`: The address and port of the service to proxy to
- `mints`: List of Cashu mints to accept tokens from
- `cost`: Cost in satoshis per request
- `min_lock_time`: How long tokens are valid after payment (in seconds)
- `secret_key`: Secret key for P2PK conditions (required)
- `db_path`: Optional custom path for the database

## Usage

### Starting the Proxy

```bash
./target/release/cashu-proxy
```

### Client Usage

Clients need to include a valid Cashu token in the `X-Cashu` header:

```
GET /api/resource HTTP/1.1
Host: example.com
X-Cashu: cashuAeyJ0b2tlbiI6W3sibWludCI6Imh0dHBzOi8vbm9mZWVzLnRlc3RudXQuY2FzaHUuc3BhY2UiLCJwcm9vZnMiOlt7ImlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwiYW1vdW50IjoxLCJzZWNyZXQiOiIwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMCIsIkMiOiIwMjg4NmY1ZjdmYzMzMjBjODNmNTc5ZTI3Y2IzNmRhNGM4MDAwNzIxMDVlZWMzOTJhYmVkNThhMTc4ODRhYjZhIiwiaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDAifV19XQ==
```

If no token is provided or the token is invalid, the proxy will respond with a 402 Payment Required status and include a payment request in the `X-Cashu` header.

## Development

### Prerequisites

- Rust
- Cargo

### Building

```bash
cargo build
```

### Testing

```bash
cargo test
```

## License

[MIT License](LICENSE)
