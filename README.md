# mitm-blockpage

`mitm-blockpage` is a small HTTPS block-page service for network filtering setups that redirect blocked TLS traffic to a local endpoint.

It generates a local certificate authority, creates per-host leaf certificates from the incoming SNI value, and serves a configurable block page over HTTPS. It also exposes the generated CA certificate so managed clients can install the CA into their trust store.

## What It Does

- Serves a self-contained block page for all blocked HTTPS requests.
- Generates and caches per-domain certificates at runtime.
- Creates a local CA automatically on first start.
- Exposes the CA as PEM at `/ca.crt` and DER at `/cert.cer`.
- Provides `/healthz` for container and load balancer checks.
- Supports custom block-page HTML through `BLOCK_PAGE_PATH`.

## Important Security Notes

This project creates a local CA private key and uses it to sign certificates dynamically. Treat the generated `ssl/ca_key.pem` as sensitive secret material.

- Do not commit generated `ssl/` contents.
- Restrict access to the host or volume that stores the CA key.
- Use only in environments where users and administrators understand and approve TLS interception.
- Rotate the CA if the key is exposed.

## Quick Start With Docker Compose

```sh
docker compose up --build
```

By default Compose exposes the service on host port `443` and stores the generated CA files in a Docker volume named `ca-data`.

To use another host port:

```sh
HOST_PORT=8443 docker compose up --build
```

Then open:

- `https://localhost/healthz`
- `https://localhost/ca.crt`
- `https://localhost/cert.cer`

The certificate endpoints use the generated CA certificate. Install the CA certificate only on devices that should trust this block page. The CA private key remains in the Docker volume and is not exposed by an endpoint.

## Local Development

This project builds with Go 1.26 or newer.

```sh
go test ./...
go run .
```

The application defaults to listening on `0.0.0.0:443` when run directly. Use a high port for local development if you do not want to run with elevated privileges:

```sh
LISTEN_ADDR=127.0.0.1 LISTEN_PORT=8443 go run .
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0` | Address the HTTPS server binds to. |
| `LISTEN_PORT` | `443` | Port the HTTPS server binds to. The Docker image sets this to `8443`. |
| `CA_CERT_PATH` | `ssl/ca_cert.pem` | Path to the local CA certificate in PEM format. |
| `CA_KEY_PATH` | `ssl/ca_key.pem` | Path to the local CA private key. |
| `BLOCK_PAGE_PATH` | `webroot/block.html` | HTML template rendered for blocked requests. |
| `WEBROOT_DIR` | `webroot` | Directory served below `/webroot/` for optional static assets. |
| `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown timeout. |

## Custom Block Page

The block page is parsed as a Go HTML template. The default template is self-contained and does not depend on external fonts, CSS, or JavaScript.

Available template fields:

| Field | Description |
| --- | --- |
| `{{ .RequestedURL }}` | Full requested URL assembled from scheme, host, and path. |
| `{{ .Host }}` | Request host. |
| `{{ .Path }}` | Request path and query string. |

Example:

```html
<h1>Access blocked</h1>
<p>{{ .RequestedURL }} is blocked by policy.</p>
```

## Endpoints

| Endpoint | Description |
| --- | --- |
| `/` | Block page fallback for all requests. |
| `/healthz` | Returns `ok` after the CA and block page are loaded. |
| `/ca.crt` | CA certificate in PEM format. |
| `/cert.cer` | CA certificate in DER format, useful for Windows import flows. |
| `/webroot/*` | Optional static files from `WEBROOT_DIR`. |

## How It Fits Into a Network

This service does not decide what to block. A firewall, DNS filter, proxy, or policy engine should redirect blocked destinations to this service. `mitm-blockpage` is only responsible for presenting a trusted HTTPS response once traffic arrives.

See [ROADMAP.md](ROADMAP.md) for planned improvements and open decisions.
