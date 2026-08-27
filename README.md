# myssh

High-performance, multi-protocol SSH tunneling core and proxy engine supporting advanced transport layers, ARQ reliable UDP, Noise encryption, and HTTP multiplexing.

## 🌐 Supported Protocols & Server Implementations

| Protocol / Tunnel | Description | Server Implementation |
| :--- | :--- | :--- |
| **`UDP_CUSTOM`** | Lightweight, reliable ARQ UDP stream tunnel with sliding-window anti-replay, multi-PSK, and Noise encryption | 🔗 [**NNdroid/udp_custom**](https://github.com/NNdroid/udp_custom) |
| **`H2` / `H2C` / `H3` / `WT` / `MASQUE` / `GRPC`** | All-in-one high-performance HTTP/2, HTTP/3 (QUIC), WebTransport, MASQUE (RFC 9298), and gRPC multiplexing tunnel with auto TLS and health probes | 🔗 [**NNdroid/h2tunnel**](https://github.com/NNdroid/h2tunnel) |
| **`XHTTP` / `XHTTPC`** | Modern Chunked / Split-HTTP streaming tunnel with ring buffer for CDN, WAF, and reverse proxy camouflage | 🔗 [**NNdroid/xhttptunnel**](https://github.com/NNdroid/xhttptunnel) |
| **`DNS` / `DNS_CUSTOM`** | Tunnel traffic through DNS queries with 8 record types, Noise_NK AEAD encryption, and UDP/DoH/DoT upstream | 🔗 [**NNdroid/dns_custom**](https://github.com/NNdroid/dns_custom) / [**dnstt**](https://www.bamsoftware.com/software/dnstt/) |
| **`KCP`** | High-performance ARQ reliable UDP with Reed-Solomon FEC forward error correction | 🔗 [**xtaci/kcptun**](https://github.com/xtaci/kcptun) |
| **`WSS` / `WS`** | WebSocket stream tunnel with CDN & reverse proxy support (Cloudflare, Nginx, Caddy) | 🔗 [**erebe/wstunnel**](https://github.com/erebe/wstunnel) / [**Nginx**](https://nginx.org) |
| **`TLS` / `HTTP`** | Standard HTTP CONNECT & TLS SNI proxy | 🔗 [**Squid**](http://www.squid-cache.org/) / [**HAProxy**](https://www.haproxy.org/) |
| **`BASE (Direct)`** | Direct TCP SSH connection | 🔗 [**OpenSSH**](https://www.openssh.com/) |
