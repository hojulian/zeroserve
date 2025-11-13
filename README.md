# zeroserve

Zero-config, fast `io_uring`-based HTTPS server.

`zeroserve` serves a website packaged as a tarball, and handles hot-reload via SIGHUP.

## Features

- Built-in TLS support
- All network and disk I/O use `io_uring`
- Clean - does not leave any temporary files on disk. Tarballs are indexed during loading (path -> byte-range), and served via byte-range reads on the tarball directly.

## Dependencies

- `monoio`: the `io_uring` runtime
- `clap`: Argument parser (use derive macro)
- `monoio-http` and `monoio-rustls`: HTTP + TLS server
- `tar`: Tarball handling
- `signal-hook`: Signal handling

## Usage

```bash
# Serve HTTP on port 8080
zeroserve --addr 0.0.0.0:8080 site.tar

# Serve HTTP on port 8080, and HTTPS on port 8443
zeroserve --addr 0.0.0.0:8080 --tls-addr 0.0.0.0:8443 --cert certificate.pem --key key.pem site.tar

# Fall back to <path>.html when a request path is missing
zeroserve --addr 0.0.0.0:8080 --try-html site.tar

# Honor PROXY protocol v1 headers (e.g. when behind a TCP load balancer)
zeroserve --enable-proxy-protocol site.tar

# Hot-reload certificate and site tarball
killall -SIGHUP zeroserve
```
