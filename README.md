# myssh

High-performance, multi-protocol SSH tunneling core and proxy engine supporting advanced transport layers, ARQ reliable UDP, and HTTP multiplexing.

## 🌐 Supported Protocols & Server Implementations

| Protocol / Tunnel | Description | Server Implementation |
| :--- | :--- | :--- |
| **`UDP_CUSTOM`** | Lightweight, reliable ARQ UDP stream tunnel with connection migration and PSK auth | 🔗 [**NNdroid/udp_custom**](https://github.com/NNdroid/udp_custom) |
| **`H2` / `H2C`** | Multiplexed HTTP/2 tunnel with AWS TLS masquerading and multi-token auth | 🔗 [**NNdroid/h2tunnel**](https://github.com/NNdroid/h2tunnel) |
| **`XHTTP` / `XHTTPC`** | Modern Chunked / Split HTTP streaming tunnel for CDN and WAF compatibility | 🔗 [**NNdroid/xhttptunnel**](https://github.com/NNdroid/xhttptunnel) |
| **`KCP`** | High-performance ARQ reliable UDP with Reed-Solomon FEC forward error correction | 🔗 [**xtaci/kcptun**](https://github.com/xtaci/kcptun) |
| **`DNS`** | Tunnel SSH traffic through DNS queries (Raw UDP, DoH, DoT) for restricted captive portals | 🔗 [**dnstt**](https://www.bamsoftware.com/software/dnstt/) / [**iodine**](https://github.com/yarrick/iodine) |
| **`WSS` / `WS`** | WebSocket stream tunnel with CDN & reverse proxy support (Cloudflare, Nginx, Caddy) | 🔗 [**erebe/wstunnel**](https://github.com/erebe/wstunnel) / [**Nginx**](https://nginx.org) |
| **`TLS` / `HTTP`** | Standard HTTP CONNECT & TLS SNI proxy | 🔗 [**Squid**](http://www.squid-cache.org/) / [**HAProxy**](https://www.haproxy.org/) |
| **`QUIC` / `H3` / `WT`** | Next-generation QUIC, HTTP/3, and WebTransport low-latency datagram tunnels | 🔗 [**dushixiang/quic-tun**](https://github.com/dushixiang/quic-tun) / [**ginuerzh/gost**](https://github.com/ginuerzh/gost) |
| **`GRPC` / `GRPCC`** | High-concurrency gRPC bidirectional streaming tunnel | 🔗 [**ginuerzh/gost**](https://github.com/ginuerzh/gost) / [**caddyserver/caddy**](https://github.com/caddyserver/caddy) |
| **`MASQUE`** | RFC 9298 IP / UDP Proxying over HTTP/3 (QUIC) | 🔗 [**cloudflare/masque-go**](https://github.com/cloudflare/masque-go) / [**h2o/h2o**](https://github.com/h2o/h2o) |
| **`BASE (Direct)`** | Direct TCP SSH connection | 🔗 [**OpenSSH**](https://www.openssh.com/) |