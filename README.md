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

## SDK tunnel configuration

Performance and lifecycle options (JSON / web profile):

- `tcp_buffer_kb` / `tcpBufferKB`: 0 leaves socket buffers to the operating
  system; 1–16384 sets each TCP socket's receive/send buffer in KiB.
- `udp_max_sessions` / `udpMaxSessions`: 0 defaults to 1024 concurrent direct
  and UDPGW sessions combined; 1–65536 overrides the limit.
- `udp_idle_timeout_sec` / `udpIdleTimeoutSec`: 0 defaults to 60 seconds;
  1–86400 overrides it. Successful application reads or writes refresh activity;
  transport keepalives do not. Idle sessions are swept once per second.

SOCKS5 UDP ingress uses 16 FIFO workers, each with a queue of 32 packets.
Packets beyond queue capacity are dropped before payload allocation; the
`UdpQueueDrops` traffic snapshot counter records overload drops. Packets for
the same client/destination use the same worker. Full-size datagrams are
accepted; fragmented SOCKS5 UDP packets remain unsupported.

TCP relays preserve half-close and cancel on engine shutdown. On Linux/Android,
plain TCP relays use splice through Go's network poller, including tracked
connections, while SSH/TLS/protocol wrappers retain their Read/Write semantics.
Start/Stop serialize engine replacement and drain the previous listener and
connection loop before starting a new engine. GOMAXPROCS follows runtime and
environment defaults.

`myssh` embeds the public client APIs from `h2tunnel`, `xhttptunnel`,
`udp_custom`, and `dns_custom`. The main process still starts with
`myssh -conf config.json`; the tunnel-specific JSON fields are:

- H2/H3/WT/MASQUE/gRPC: `proxy_addr`, `custom_path`, `custom_host`,
  `server_name`, `proxy_auth_required`, `proxy_auth_token`, and
  `heartbeat_interval_ms`.
- XHTTP/XHTTPC: the common HTTP fields plus `alpn` (`auto`, `h3`, `h2`, or
  `h1`) and `xhttp_chunk_size_kb`.
- UDP custom: `udp_custom_psk` (required by protocol v2),
  `udp_custom_magic`, `udp_custom_public_key`, `udp_custom_paths`,
  `udp_custom_sockets`, and `udp_custom_send_window`.
- DNS custom: `dns_tunnel_domain`, `dns_tunnel_servers`,
  `dns_tunnel_type`, `dns_tunnel_public_key`, and `dns_tunnel_edns0`.

The requested backend is always the configured `ssh_addr`. Server-side
`allowed_targets` must permit that target for deployments that enable target
ACLs. DNS EDNS0 must be enabled end-to-end. XHTTP request and response chunk
sizes may differ, but both must stay below the CDN or reverse-proxy body limit.
