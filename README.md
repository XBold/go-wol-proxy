# Go WOL Proxy

A Wake-on-LAN proxy service written in Go that automatically wakes up servers when requests are made to them.

## Features

- Proxies HTTP requests to configured target servers
- Automatically sends Wake-on-LAN packets to wake up offline servers
- Monitors server health with configurable intervals
- Caches health status to minimize latency for frequent requests
- **Caches HTTP responses to disk** - serves stale content when destinations are offline, preventing unnecessary wake-ups
- Packaged as a Docker container for easy deployment
- :star: new :star: Supports graceful shutdown of servers after a period of inactivity

## Configuration

The service is configured using a TOML file. Here's an example configuration:

```toml
port = ":8080"                  # Port to listen on
timeout = "1m"                  # How long to wait for server to wake up
response_header_timeout = "1m"  # How long to wait for a response header, e.g. during or after slow or long-running requests/uploads
health_check_interval = "30s"   # Background health check frequency
health_cache_duration = "10s"   # How long to trust cached health status

# Static response cache - serves cached content when destinations are offline
# Prevents unnecessary WOL triggers for cached paths
[cache]
enabled = false                              # Enable static response caching
root_path = "./cache"                        # Directory to store cached responses
ttl = "24h"                                  # How long cached entries remain valid
max_response_size_bytes = 10485760           # Maximum response size to cache (10MB)
warm_interval = "30m"                        # How often to refresh cache when target is healthy

[[cache.targets]]
target = "service"                           # Target name (must match a target's name field)
paths = ["/docs", "/assets", "/static/*"]    # Paths to cache (supports /* wildcard)

# Optional SSL configuration Do not add these values unless you plan to use TLS/HTTPS
ssl_certificate = "/path/to/cert.pem"   # Path to your SSL certificate
ssl_certificate_key = "/path/to/key.pem" # Path to your SSL private key


[[targets]]
name = "service"
hostname = "service.host.com"                 # The "external" hostname - what this server receives as a Host header
destination = "http://service.local"          # The actual url to the server
health_endpoint = "http://service.local/ping" # url to check health
mac_address = "7c:8b:ad:da:be:51"             # MAC address for WOL
broadcast_ip = "10.0.0.255"                   # Broadcast IP for WOL
wol_port = 9                                  # Port for WOL packets
# Optional: Graceful shutdown configuration (SSH or HTTP)
inactivity_threshold = "1h"                   # Shut down after 1 hour of inactivity

# Option A: SSH-based shutdown (use either Option A or Option B, not both)
ssh_host = "service.local:22"                 # SSH host:port for shutdown
ssh_user = "wol-proxy"                        # SSH username for shutdown
ssh_key_path = "/app/private_key"             # Path to SSH private key
ssh_known_hosts = "/app/known_hosts"          # Path to known_hosts file (optional; omits host key verification if unset)
shutdown_command = "sudo systemctl suspend"   # Command to execute for shutdown
# ^ take care - wake from suspend / shutdown can be flaky on some systems.
# if your machine doesnt wake from your chosen "sleep" mode, try another.

# Option B: HTTP-based shutdown (use either Option A or Option B, not both)
#shutdown_http_url = "http://service.local/api/shutdown" # URL to trigger shutdown (final response validated)
#shutdown_http_method = "POST"                              # Optional; defaults to POST
#shutdown_http_ok_status = 0                                 # Optional; 0=accept any 2xx (default). Set e.g. 202 to require specific code

[[targets]]
name = "service2"
hostname = "service2.host.com"
destination = "http://service2.local"
health_endpoint = "http://service2.local/ping"
mac_address = "c9:69:45:d2:1e:12"
broadcast_ip = "10.0.0.255"
wol_port = 9
```

## Docker Usage

### Pull the Docker Image

```bash
docker pull ghcr.io/XBold/go-wol-proxy:latest
```

### Run the Docker Container

```bash
# Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
docker run --network host -v /path/to/config.toml:/app/config.toml ghcr.io/XBold/go-wol-proxy:latest
```

### Build the Docker Image Locally

```bash
docker build -t go-wol-proxy .
```

### Run the Locally Built Image

```bash
# Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
docker run --network host -v /path/to/config.toml:/app/config.toml go-wol-proxy
```

### Docker Compose Usage

Create a `docker-compose.yml` file with the following content:

```yaml
version: '3'

services:
  go-wol-proxy:
    image: ghcr.io/XBold/go-wol-proxy:latest
    # Note: network mode "host" is required for Wake-on-LAN packets to be sent correctly
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./config.toml:/app/config.toml
      # Optional: SSH private key and known_hosts for graceful shutdown
      - ./private_key:/app/private_key
      # Optional: known_hosts file for SSH host key verification
      # - ./known_hosts:/app/known_hosts
```

Run the container with Docker Compose:

```bash
docker-compose up -d
```

## Graceful Shutdown Options

- Trigger a shutdown after a period of inactivity using SSH or HTTP.
- Exactly one mechanism must be configured per target: SSH or HTTP, not both.

### SSH-based Shutdown
- Use `ssh_host`, `ssh_user`, `ssh_key_path`, and `shutdown_command`.
- Optionally set `ssh_known_hosts` to enable host key verification (uses `InsecureIgnoreHostKey()` if unset).
- The proxy executes the command over SSH when the target is inactive.

### HTTP-based Shutdown
- Use `shutdown_http_url` to enable HTTP shutdown.
- `shutdown_http_method` defaults to `POST` if not specified.
- By default, any 2xx status code counts as success; set `shutdown_http_ok_status` to require a specific code.
- The HTTP client follows redirects and validates the final response code.
- The shutdown HTTP request uses a 10s timeout.

### Validation Rules
- You cannot set both `shutdown_http_url` and `shutdown_command` for the same target.
- If `shutdown_http_method` and/or `shutdown_http_ok_status` are set, `shutdown_http_url` must also be set.

## Static Response Cache

When enabled, the proxy caches HTTP responses for configured paths to disk. This provides several benefits:

- **No unnecessary wake-ups**: When a destination is offline, cached responses are served instead of triggering WOL
- **Faster responses**: Cached content is served instantly without waiting for the server to wake up
- **Automatic warming**: Cache is refreshed when targets wake up and periodically (default every 30 minutes)

### How It Works

1. **Caching**: Successful GET responses to configured paths are saved to disk
2. **Serving**: When a destination is down and a cached response exists for the requested path, it's served immediately
3. **Invalidation**: Cache is cleared when a target wakes up (ensures fresh content after wake)
4. **Warming**: After invalidation, the proxy fetches all configured paths to rebuild the cache

### Configuration

- `enabled`: Turn the feature on/off (disabled by default)
- `root_path`: Directory for cached files (default: `./cache`)
- `ttl`: How long entries remain valid (default: 24h)
- `max_response_size_bytes`: Skip caching responses larger than this (default: 10MB)
- `warm_interval`: How often to refresh cache for healthy targets (default: 30m)

### Path Patterns

- Exact match: `"/docs"` caches only `/docs`
- Wildcard: `"/static/*"` caches any path starting with `/static/`

### Docker Volumes

If using Docker and enabling the cache, mount the cache directory to persist across restarts:

```bash
docker run --network host \
  -v /path/to/config.toml:/app/config.toml \
  -v /path/to/cache:/app/cache \
  ghcr.io/XBold/go-wol-proxy:latest
```

### Similar projects:
1. traefik-wol: [traefiklabs](https://plugins.traefik.io/plugins/642498d26d4f66a5a8a59d25/wake-on-lan), [github](https://github.com/MarkusJx/traefik-wol)
2. caddy-wol: [github](https://github.com/dulli/caddy-wol)

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and commit conventions.
