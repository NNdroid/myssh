# myssh

High-performance, multi-protocol SSH tunneling core and proxy engine. A standard
SSH session is carried over HTTP/2, HTTP/3 (QUIC), WebSocket, MASQUE, gRPC,
XHTTP, plain TCP/TLS, or an ARQ/Noise-encrypted UDP, DNS, or ICMP channel; the
engine then exposes a local SOCKS5/HTTP proxy.

## 🌐 Supported Transports (`tunnel_type`)

`tunnel_type` is case-insensitive and defaults to `raw` when empty. TLS is
selected per type as shown below — see [docs/transports.md](docs/transports.md)
for the full parameter reference.

| `tunnel_type` | Description | TLS | Server implementation |
| :--- | :--- | :--- | :--- |
| **`raw`** | SSH over TCP. Direct when TLS is off; uTLS Chrome-fingerprinted TLS with SNI spoofing when on. | toggle | 🔗 [**OpenSSH**](https://www.openssh.com/) |
| **`http`** | Plain HTTP `CONNECT` proxy. | none | 🔗 [**Squid**](http://www.squid-cache.org/) / [**HAProxy**](https://www.haproxy.org/) |
| **`websocket`** | WebSocket stream for CDN / reverse-proxy camouflage; the TLS toggle selects `ws` or `wss`. | toggle | 🔗 [**wstunnel**](https://github.com/erebe/wstunnel) / Nginx / Caddy / Cloudflare |
| **`h2`** | HTTP/2 multiplexing; `h2c` (cleartext) when the TLS toggle is off. | toggle | 🔗 [**NNdroid/h2tunnel**](https://github.com/NNdroid/h2tunnel) |
| **`grpc`** | gRPC multiplexing. | toggle | 🔗 [**NNdroid/h2tunnel**](https://github.com/NNdroid/h2tunnel) |
| **`h3`** | HTTP/3 over QUIC. | always on | 🔗 [**NNdroid/h2tunnel**](https://github.com/NNdroid/h2tunnel) |
| **`webtransport`** | WebTransport over HTTP/3. | always on | 🔗 [**NNdroid/h2tunnel**](https://github.com/NNdroid/h2tunnel) |
| **`masque`** | MASQUE (RFC 9298). | always on | 🔗 [**NNdroid/h2tunnel**](https://github.com/NNdroid/h2tunnel) |
| **`quic`** | SSH over a raw QUIC stream; ALPN is fixed to `h3`. | always on | SSH-over-QUIC server |
| **`xhttp`** | Chunked / split-HTTP streaming with a ring buffer, for CDN, WAF, and reverse-proxy camouflage. | toggle | 🔗 [**NNdroid/xhttptunnel**](https://github.com/NNdroid/xhttptunnel) |
| **`kcptun`** | KCP + Snappy + SMUX over UDP, with Reed-Solomon FEC. | none | 🔗 [**xtaci/kcptun**](https://github.com/xtaci/kcptun) / kcptun-rs |
| **`udp_custom`** | ARQ UDP stream with sliding-window anti-replay, multi-PSK, Noise, adaptive FEC and recovery. | none | 🔗 [**NNdroid/udp_custom**](https://github.com/NNdroid/udp_custom) |
| **`dns_custom`** | SSH over DNS queries with multiple record types, Noise AEAD, and UDP/DoT/DoH upstreams. | none | 🔗 [**NNdroid/dns_custom**](https://github.com/NNdroid/dns_custom) / [**dnstt**](https://www.bamsoftware.com/software/dnstt/) |
| **`icmp_custom`** | SSH over ICMP echo with PSK + Noise and automatic MTU probing. | none | 🔗 [**NNdroid/icmp_custom**](https://github.com/NNdroid/icmp_custom) |

> `h2c`, `ws`/`wss`, and direct SSH are **modes of the transports above**, not
> separate `tunnel_type` values — they are selected with `tunnel_tls_enabled`.

## SDK / JSON configuration

The engine embeds the public client APIs from `h2tunnel`, `xhttptunnel`,
`udp_custom`, `dns_custom`, and `icmp_custom`. The main process starts with
`myssh -conf config.json`; the Android AAR uses the same JSON schema.

### Connection and TLS

- `ssh_addr`: the SSH endpoint every transport ultimately reaches.
- `tunnel_tls_enabled`: TLS switch for the merged types (`raw`, `websocket`,
  `h2`, `grpc`, `xhttp`). `h3` / `webtransport` / `masque` / `quic` are always
  TLS; `http` / `kcptun` / `udp_custom` / `dns_custom` / `icmp_custom` have no
  TLS concept and ignore it.
- `server_name`: TLS SNI. `verify_certificate_finger_print` +
  `server_certificate_finger_print`: optional leaf-certificate SHA-256 pinning
  (all TLS transports share the same `InsecureSkipVerify` + pin-or-don't-care
  model; see [docs/transports.md](docs/transports.md)).
- `verify_ssh_finger_print` + `server_ssh_finger_print`: SSH host-key pinning.
- `bind_interface`: outbound interface binding; empty means unbound.
- `proxy_auth_token` (Bearer/PSK: `h2` family, `xhttp`) and
  `proxy_auth_user` / `proxy_auth_pass` (Basic: `websocket` / `http`).

### Resource limits

- `tcp_buffer_kb`: 0 leaves socket buffers to the OS; 1–16384 sets each TCP
  socket's receive/send buffer in KiB.
- `udp_max_sessions`: 0 defaults to 1024 concurrent direct and UDPGW sessions
  combined; 1–65536 overrides the limit.
- `udp_idle_timeout_sec`: 0 defaults to 60 seconds; 1–86400 overrides it.
  Successful application reads or writes refresh activity; transport keepalives
  do not. Idle sessions are swept once per second.

### Transport-specific fields

- **`h2` / `grpc` / `h3` / `webtransport` / `masque`**: `proxy_addr`,
  `custom_path`, `custom_host`, `server_name`, `heartbeat_interval_ms`,
  `padding_min_bytes`; `masque` also reads `masque_alpn` (`auto` / `h3` / `h2`).
- **`xhttp`**: the common HTTP fields plus `alpn` (`auto` / `h3` / `h2` / `h1`),
  `xhttp_chunk_size_kb` (0 → 256, 16–900), and `xhttp_stream_mode`
  (`auto` / `stream` / `poll`).
- **`kcptun`**: `kcp_password`, `kcp_crypt`, `kcp_mode`, `kcp_data_shards`,
  `kcp_parity_shards`, `kcp_sndwnd`, `kcp_rcvwnd`, `kcp_mtu`, `kcp_nocomp`,
  `kcp_smuxver`, `kcp_keepalive`.
- **`udp_custom`**: `udp_custom_psk` (required by protocol v2),
  `udp_custom_magic`, `udp_custom_public_key`, `udp_custom_paths`,
  `udp_custom_sockets`, `udp_custom_send_window`, `udp_custom_max_pkt`,
  `udp_custom_mtu_probe`.
- **`dns_custom`**: `dns_tunnel_domain`, `dns_tunnel_servers`,
  `dns_tunnel_type`, `dns_tunnel_public_key`, `dns_tunnel_edns0`,
  `dns_tunnel_psk`, `dns_tunnel_marker`.
- **`icmp_custom`**: `icmp_custom_psk`, `icmp_custom_magic`,
  `icmp_custom_public_key`, `icmp_custom_mtu_mode`,
  `icmp_custom_max_payload`, `icmp_custom_pace_ms`, `icmp_custom_id_range`.

DNS EDNS0 must be enabled end-to-end. XHTTP request and response chunk sizes may
differ, but both must stay below the CDN or reverse-proxy body limit.

## Data plane

SOCKS5 UDP ingress uses 16 FIFO workers, each with a queue of 32 packets.
Packets beyond queue capacity are dropped before payload allocation; the
`UdpQueueDrops` traffic snapshot counter records overload drops. Packets for the
same client/destination use the same worker. Full-size datagrams are accepted;
fragmented SOCKS5 UDP packets remain unsupported.

TCP relays preserve half-close and cancel on engine shutdown. On Linux/Android,
plain TCP relays use splice through Go's network poller, including tracked
connections, while SSH/TLS/protocol wrappers retain their Read/Write semantics.
Start/Stop serialize engine replacement and drain the previous listener and
connection loop before starting a new engine. GOMAXPROCS follows runtime and
environment defaults.

## Android (gomobile) entry points

All engine state lives in package-level globals, so `NewSshTProxy()` returns an
equivalent empty facade and every method is safe to call on any instance.

Engine callbacks are **dispatched asynchronously** through a bounded queue
(512 events, drop-oldest, counter via `GetDroppedEventCount()`). The engine
never waits for the host, so it is safe to call `Stop()` or `Start()` from
inside `OnState`.

| Call | Why it matters |
| --- | --- |
| `Start(configJson) int` / `StartAsync(configJson, cb)` | `StartAsync` keeps the Android main thread free while a previous engine is being torn down. |
| `Stop()` / `StopAsync()` | |
| `GetState()`, `IsRunning()`, `GetLastError()` | Read the true engine state after re-registering a callback (e.g. after Activity recreation). |
| `NotifyNetworkChanged()` | Wi-Fi ↔ cellular switch: drops DNS upstream pools and closes the SSH session so the reconnect starts immediately instead of after the next keepalive (18s tick + 8s timeout). |
| `ClearEngineCallback()`, `ClearTrafficCallback()`, `ClearSysInfoCallback()`, `ClearLogReceiver()`, `ClearProtector()` | Release host-side references from `Activity.onDestroy`; the Go globals would otherwise keep Activity-scoped objects alive. |
| `PingNodesAsync` / `SpeedTestAsync` / `CancelPing` | Blocking latency/speed probes must not run on the main thread. |
| `InitCrashOutput(path) int` | Returns `0` on success, `-1` if the crash file cannot be opened. |

`RegisterSocketMarkHelper` / `ProbeSocketMark` must both run before `Start`,
because the first SSH dial happens synchronously inside it.
