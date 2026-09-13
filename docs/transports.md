# myssh 传输协议参数说明（Transport Parameters）

> 本文列出 `myssh` 所有 tunnel（transport）类型的完整配置参数、取值枚举、默认值与校验规则。
>
> - 配置键（JSON key）取自 [`ProxyConfig`](../config.go) 的 `json` tag；这是 Android/JNI、`cmd` 直接读入、以及 web 后端最终序列化成 JSON 的权威结构。
> - web 后端把 profiles 表（camelCase 列）经 [`ToProxyConfig`](../web/db.go) 映射为同一 `ProxyConfig`，再 `json.Marshal` 交给核心；因此本文以 **JSON key** 为准，并在末尾附 web 列名对照要点。
> - 所有 `*_finger_print`/`*_fingerprint` 类字段：值为 SHA-256 指纹，形如 `AA:BB:…:CC`（大写、冒号分隔）；比较前会剥离 `:`/空格并统一大写，故 `AABB…`、`aa:bb:…` 皆可。
> - 布尔开关缺省为 `false`；字符串留空即“走默认/不启用”。

---

## 1. 全局 / 连接级参数（所有 transport 共用）

这些字段不属于任何单一 transport，由 `proxy.go` / `dialer.go` / `dns.go` 统一消费。

| JSON key | 类型 | 说明 | 取值 / 默认 |
|---|---|---|---|
| `local_addr` | string | 本地 SOCKS5/HTTP 监听地址 | 必填 |
| `ssh_addr` | string | SSH 服务端地址 `host:port`（隧道最终要打通的目标） | 必填（自拨类 transport 会显式校验非空） |
| `tunnel_type` | string | 传输类型，取值见 §4/§5 | 必填 |
| `user` | string | SSH 用户名 | 必填 |
| `auth_type` | string | SSH 认证方式 | `password`（用 `pass`）；其它值（默认按密钥）→ 用 `private_key` |
| `private_key` | string | PEM 私钥（`auth_type != "password"` 时） | — |
| `private_key_passphrase` | string | 私钥口令（可空） | 空=无口令 |
| `pass` | string | SSH 密码（`auth_type == "password"` 时） | — |
| `verify_ssh_finger_print` | bool | 是否校验 SSH 主机密钥指纹（TOFU/pin） | `false`=接受任意主机密钥（有 MITM 风险）；`true` 须配 `server_ssh_finger_print` |
| `server_ssh_finger_print` | string | 期望的 SSH 主机密钥 SHA-256 指纹 | 上项开启时必填 |
| `dns_addr` | string | 远端 DNS | — |
| `udpgw_addr` | string | UDPGW 上游地址（DNS/UDP 转发） | 可空 |
| `udpgw_version` | string | UDPGW 实现方言 | `badvpn`（badvpn-udpgw 帧）；其它/空=tun2socks 默认帧 |
| `bind_interface` | string | 出站绑定网卡 | 空=不绑定 |

---

## 2. 通用 TLS / 代理认证参数（跨多类 transport）

仅 TLS 类 / 自拨类 transport 读取；无 TLS 概念的类型（`http`/`kcptun`/`udp_custom`/`dns_custom`/`icmp_custom`）会忽略相关字段。

| JSON key | 类型 | 说明 |
|---|---|---|
| `tunnel_tls_enabled` | bool | 合并型隧道（`raw`/`websocket`/`h2`/`grpc`/`xhttp`）的 TLS 开关。固定 TLS 的 `h3`/`webtransport`/`masque`/`quic` 恒为开，忽略此项；无 TLS 类型忽略。 |
| `proxy_addr` | string | 代理/隧道服务端 endpoint（自拨类据此构造 URL；tcp/udp 复用型由 `dialer` 预拨到此地址）。 |
| `proxy_auth_required` | bool | 是否启用代理层鉴权。 |
| `proxy_auth_user` / `proxy_auth_pass` | string | Basic 鉴权（`websocket`/`http`）。 |
| `proxy_auth_token` | string | Bearer/PSK token（`h2` 家族、`xhttp`）。`proxy_auth_required=true` 且此项为空时报错。 |
| `custom_host` | string | 覆盖请求 `Host` 头（伪装/CDN 前置）。 |
| `custom_path` | string | 覆盖请求路径（默认端点路径见各类型）。 |
| `server_name` | string | TLS SNI（Server Name Indication）。留空则各实现按 host 处理。 |
| `verify_certificate_finger_print` | bool | 是否启用**证书指纹 pinning**。 |
| `server_certificate_finger_print` | string | 期望的服务端**叶子证书** SHA-256 指纹。 |
| `alpn` | string | ALPN 协议列表（逗号分隔）。**仅 `xhttp` 读取**；`raw`/`ws`/`quic` 的 ALPN 固定不可配（见 §5）。 |
| `heartbeat_interval_ms` | int | 空闲心跳间隔（毫秒），主流被 CDN/反代 idle 掐断前主动保活。**仅 `h2` 家族（`h2`/`grpc`/`h3`/`webtransport`/`masque`）读取**。`0`→默认 25000ms；`<0` 报错。 |

### TLS 证书信任模型（重要，勿误判为 bug）

所有 TLS 类 transport（`raw`/`websocket`/`quic`/`h2`/`grpc`/`h3`/`webtransport`/`masque`/`xhttp`）共用同一约定：

- `InsecureSkipVerify` **恒为 true**——系统根 CA 链校验被关闭，**不信任任何 CA**。
- 服务端身份**只**由 `verify_certificate_finger_print` 决定的指纹比对兜底：
  - `false` → **完全接受任意证书**（含中间人）。这是“pin-or-don't-care”设计，不是漏洞。`xhttp` 侧（SDK）此时还会额外打一条 “未配置指纹，存在 MITM 风险” 的 Warn。
  - `true` → 计算叶子证书 DER 的 SHA-256，与 `server_certificate_finger_print` 比对，不匹配则握手直接失败（纯证书锁定，免疫伪造 CA）。
- 实现路径：`raw`/`ws` 经 `buildUTLSConfig`；`h2` 家族经 `sdkTLSConfig` + `sdkQUICDialer`（把同一 `tls.Config` 交给 `quic.DialEarly`）；`quic` 直接调 `MakePeerCertVerifier`；`xhttp` 走 xhttptunnel SDK 内的 `verifyFingerprint`（同为叶子证书 SHA-256，指纹值可跨隧道通用）。
- 边界一致性：`verify=true` 却留空指纹时，`raw`/`ws`/`quic`/`h2` 家族的 `MakePeerCertVerifier` 会因 `""≠实际` 而**失败关闭**；`xhttp` 现也在 `dialXHTTPSDK` 里对 TLS 场景做了同样的 fail-closed 预检（`tlsEnabled && verify && 指纹为空` → 建连前报错）。
- ClientHello 伪装：TLS 类走 **uTLS Chrome 指纹**（`HelloChrome_Auto`）。myssh **自带 DNS 解析器**的 DoT 上游与证书探测（`FetchCertInfo`/`probeTLSCert`）也已 uTLS 化（经 `newChromeUConn`，见 [`utils.go`](../utils.go)）；但 `dns_custom` 隧道自身的 DoT/DoH 上游走标准 crypto/tls（无握手注入点），`quic`/`h3`/`webtransport`/`masque` 因 quic-go 无 ClientHello 钩子也无法 uTLS 化。

---

## 3. Transport 总览

| 类型 (`tunnel_type`) | 网络 | TLS 模型 | 拨号方式 | 底层实现 |
|---|---|---|---|---|
| `raw` | tcp | 可切换 | 复用 baseConn（预拨 `proxy_addr`） | uTLS Chrome + SSH |
| `websocket` | tcp | 可切换（wss/ws） | 复用 baseConn | uTLS Chrome（wss）+ WS |
| `http` | tcp | 无（明文 CONNECT） | 复用 baseConn | 标准 HTTP 代理 |
| `h2` | custom | 可切换（TLS→`h2` / 明文→`h2c`） | 自拨 | h2tunnel SDK |
| `grpc` | custom | 可切换 | 自拨 | h2tunnel SDK |
| `h3` | custom | **固定 TLS**（忽略开关） | 自拨 | h2tunnel SDK（quic-go） |
| `webtransport` | custom | **固定 TLS**（h3 之上） | 自拨 | h2tunnel SDK |
| `masque` | custom | **固定 TLS** | 自拨 | h2tunnel SDK |
| `quic` | udp | 固定 TLS | 复用 baseConn（udp） | quic-go，ALPN 固定 `h3` |
| `xhttp` | custom | 可切换 | 自拨 | xhttptunnel SDK |
| `kcptun` | udp | 无 TLS（KCP+Snappy+SMUX，密钥/加密另配） | 复用 baseConn（udp） | 内置 kcptun 协议栈 |
| `udp_custom` | custom | 无 TLS（PSK + Noise） | 自拨 | udp_custom SDK |
| `dns_custom` | custom | 无 TLS（Noise + PSK，走 DNS 报文） | 自拨 | dns_custom SDK |
| `icmp_custom` | custom | 无 TLS（PSK + Noise，走 ICMP） | 自拨 | icmp_custom SDK |

> 说明：`h2`/`grpc`/`h3`/`webtransport`/`masque` 全部汇入 `tunnel_h2.go dialH2SDK` + `tunnel_sdk.go` 的 `sdkProxyEndpoint`/`sdkTLSConfig`/`sdkTCPDialer`/`sdkQUICDialer`；`h3`/`masque`/`webtransport` 只是一行 `registerH2SDK(name, transport, tlsEnabled=true)`。因此它们的参数与 `h2` 基本一致，差别仅在“TLS 恒开、走 QUIC”。

---

## 4. 逐 Transport 参数

下面每类只列**该类额外读取的字段**；§1 的全局字段与 §2 的通用 TLS/认证字段按“适用”叠加。

### 4.1 `raw`（tcp，可切换 TLS）
- 读：`server_name`、`tunnel_tls_enabled`、`verify_certificate_finger_print`、`server_certificate_finger_print`
- ALPN：**固定** `["h2","http/1.1"]`（与 Chrome 默认一致，不可配——改 ALPN 会改变 JA4 指纹画像）
- `tunnel_tls_enabled=false` 时退化为裸 TCP（不包 TLS）

### 4.2 `websocket`（tcp，可切换 wss/ws）
- 读：`custom_host`、`custom_path`、`proxy_addr`、`proxy_auth_required`、`proxy_auth_user`、`proxy_auth_pass`、`server_name`、`tunnel_tls_enabled`、`verify/server_certificate_finger_print`
- ALPN：固定 `["http/1.1"]`（WS 无 h2/h3）
- 默认路径见 SDK；`custom_path` 可覆盖

### 4.3 `http`（tcp，明文 HTTP CONNECT）
- 读：`custom_host`、`http_payload`、`proxy_auth_required`、`proxy_auth_user`、`proxy_auth_pass`、`disable_status_check`、`proxy_addr`、`ssh_addr`
- 无 TLS，忽略 `tunnel_tls_enabled` 与证书指纹字段
- `http_payload`：自定义 CONNECT/请求头模板；`disable_status_check`：跳过连通性状态探测

### 4.4 `h2` / `grpc`（custom，可切换 TLS）
- 读：`custom_host`、`custom_path`（默认 `/tunnel`）、`proxy_addr`、`proxy_auth_required`、`proxy_auth_token`、`heartbeat_interval_ms`、`padding_min_bytes`、`tunnel_tls_enabled`；TLS 叠加 `server_name`、`verify/server_certificate_finger_print`
- `h2`：`tunnel_tls_enabled=true`→`TransportH2`（TLS），`false`→`TransportH2C`（明文）
- `grpc`：由 `tunnel_tls_enabled` 决定是否 TLS，走 `TransportGRPC`
- uTLS：h2tunnel SDK 现自带 Chrome ClientHello 伪装；myssh 对 **TCP-TLS 的 h2/grpc 固定 `UtlxFingerprint="chrome"`**（不可配，与 raw/ws/xhttp 一致；QUIC 类不接受该参数）。
- `padding_min_bytes`：出站帧最小字节（流量混淆）。`0`→myssh 默认 **1420**（SDK 本身把 0 视为 900，myssh 覆写为 1420），`-1`/负数→关闭，上限 0xFFFF。
- 校验：`heartbeat_interval_ms < 0` 报错；`ssh_addr` 空报错；`proxy_auth_required=true` 且 token 空报错

### 4.5 `h3` / `webtransport` / `masque`（custom，固定 TLS，QUIC 承载）
- 参数与 §4.4 相同（含 `padding_min_bytes`），但 **`tunnel_tls_enabled` 被忽略（恒开 TLS）**；uTLS 不适用（QUIC 内部做 TLS）
- `masque` 额外读 **`masque_alpn`**（仅 masque）：承载选择，SDK 取值 `""`(auto)/`h2`/`h3`；配置面 `h3,h2`（或 `auto`/空）→auto、`h3`→仅 h3、`h2`→仅 h2
- 走 `sdkQUICDialer`（含 `bind_interface`）；ALPN 语义由 SDK 传输固定（h3/wt）

### 4.6 `quic`（udp，固定 TLS，SSH-over-QUIC）
- 读：`proxy_addr`、`server_name`、`verify_certificate_finger_print`、`server_certificate_finger_print`
- ALPN：**固定** `h3`（不可配，不可并入 raw）
- TLS 用 crypto/tls + `MakePeerCertVerifier`（**注意：非 uTLS**，quic-go v0.60 无 ClientHello 替换钩子）

### 4.7 `xhttp`（custom，可切换 TLS）
- 读：`alpn`、`custom_host`、`custom_path`（默认 `/stream`）、`proxy_addr`、`proxy_auth_required`、`proxy_auth_token`、`server_name`、`ssh_addr`、`tunnel_tls_enabled`、`xhttp_chunk_size_kb`、`xhttp_stream_mode`
- 指纹：经 SDK `verifyFingerprint` pinning（同 §2）；TLS 且 `verify=true` 空指纹 → 建连前 fail-closed 报错
- `xhttp_chunk_size_kb`：上行分块大小（KB），`0`→默认 256；**建议 16–900**；myssh 硬拒 `<0` 与 `>900`
- `xhttp_stream_mode`：下行传输，`""`/`auto`（默认，流式优先、轮询回退）、`stream`、`poll`；非法值报错
- `alpn`：唯一真正消费 `alpn` 字段的类型（逗号分隔取首个归一）

### 4.8 `kcptun`（udp，无 TLS；kcptun 协议 KCP→Snappy→SMUX→SSH）
- 读：`proxy_addr`、`ssh_addr`、`kcp_password`、`kcp_crypt`、`kcp_mode`、`kcp_data_shards`、`kcp_parity_shards`、`kcp_sndwnd`、`kcp_rcvwnd`、`kcp_mtu`、`kcp_nocomp`、`kcp_smuxver`、`kcp_keepalive`

| 字段 | 含义 | 取值 / 默认 |
|---|---|---|
| `kcp_password` | kcptun 密钥（派生 block crypt key，盐 `"kcp-go"`） | 必填 |
| `kcp_crypt` | 加密算法 | `null`/`none`/`aes-128`/`aes-192`/`aes`/`aes-128-gcm`/`sm4`/`tea`/`xtea`/`salsa20`/`blowfish`/`twofish`/`cast5`/`3des`/`xor` |
| `kcp_mode` | nodelay 预设（std.PredefinedModes） | `""`/`normal`/`fast`(默认)/`fast2`/`fast3`；未知值回落 `fast`（仅影响性能，不影响兼容） |
| `kcp_data_shards` / `kcp_parity_shards` | FEC 数据/校验分片 | 默认 10 / 3 |
| `kcp_sndwnd` / `kcp_rcvwnd` | 发送/接收窗口 | 默认 128 / 512 |
| `kcp_mtu` | MTU | 默认 1350；**非法值直接 fail-fast**（`SetMtu` 返回 false 即报错） |
| `kcp_nocomp` | 关闭会话级 Snappy 压缩 | `false`=启用压缩 |
| `kcp_smuxver` | SMUX 版本 | 1 / 2（默认 2） |
| `kcp_keepalive` | 保活秒数 | 默认 10 |

> 兼容：可与 `kcptun-rs` 固定 `-t` 服务端互通（同一密钥派生与帧格式）。

### 4.9 `udp_custom`（custom，无 TLS；PSK + Noise，多路 UDP）
- 读：`proxy_addr`、`ssh_addr`、`udp_custom_psk`、`udp_custom_magic`、`udp_custom_public_key`、`udp_custom_paths`、`udp_custom_sockets`、`udp_custom_send_window`、`udp_custom_max_pkt`、`udp_custom_mtu_probe`

| 字段 | 含义 | 取值 / 默认 |
|---|---|---|
| `udp_custom_psk` | 预共享密钥（PSK 鉴权） | 建议 ≥16 字符（短 PSK 可被在线爆破，会 Warn） |
| `udp_custom_magic` | 4 字节魔数 | 支持 `0x` 前缀 / 十六进制；空或 `0x00000000`→默认 `UDPC`（拒绝 ASCII 字面） |
| `udp_custom_public_key` | 服务端 Noise 静态公钥 | hex(64) / base64；空=仅 PSK |
| `udp_custom_paths` | 多路（随机源端口）数量 | `0`→32 |
| `udp_custom_sockets` | 本地 UDP socket 数 | `0`→1 |
| `udp_custom_send_window` | 在途帧数 | `0`→256（SDK 默认） |
| `udp_custom_max_pkt` | 单条 v2 记录上线最大字节（UDP 载荷=40 头+载荷+16 tag）；窄链路上调小可免 IP 分片丢包 | `0`→1450（历史值）；`<0` 报错。MtuProbe 开启时它是探测**上限/回落值** |
| `udp_custom_mtu_probe` | 握手后自动探测路径 MTU 阶梯并收敛 | `""`/`auto`(默认=开，遇旧服务端不应答自动回落)、`on`(强制开)、`off`(按 `udp_custom_max_pkt` 固定) |


### 4.10 `dns_custom`（custom，无 TLS；SSH-over-DNS，Noise + PSK）
- 读：`ssh_addr`、`dns_tunnel_domain`、`dns_tunnel_servers`、`dns_tunnel_type`、`dns_tunnel_public_key`、`dns_tunnel_edns0`、`dns_tunnel_psk`、`dns_tunnel_marker`

| 字段 | 含义 | 取值 / 默认 |
|---|---|---|
| `dns_tunnel_domain` | 隧道根域名（如 `tunnel.example.com`） | 必填 |
| `dns_tunnel_servers` | DNS 上游地址列表（数组） | scheme 前缀：`udp`(默认)/`tcp://`/`tls://`/`dot://`/`https://`（其 TLS 在 `miekg/dns`/`http.Transport` 内完成，**走标准 crypto/tls，非 uTLS**） |
| `dns_tunnel_type` | 承载记录类型 | `txt`(默认)/`null`/`cname`/`a` |
| `dns_tunnel_public_key` | Noise 公钥 | 可空 |
| `dns_tunnel_edns0` | 通告 1232 字节应答 | 需与服务端一致 |
| `dns_tunnel_psk` | PSK 密钥 | 空=匿名；短值 Warn |
| `dns_tunnel_marker` | 自定义标记标签 | 两端须一致；空=默认 |

### 4.11 `icmp_custom`（custom，无 TLS；SSH-over-ICMP，PSK + Noise）
- 读：`proxy_addr`、`ssh_addr`、`icmp_custom_psk`、`icmp_custom_magic`、`icmp_custom_public_key`、`icmp_custom_mtu_mode`、`icmp_custom_max_payload`、`icmp_custom_pace_ms`、`icmp_custom_id_range`

| 字段 | 含义 | 取值 / 默认 |
|---|---|---|
| `icmp_custom_psk` | PSK（**必填**） | 建议 ≥16 字符（文档明确点名可在线爆破） |
| `icmp_custom_magic` | 4 字节记录魔数（8 位 hex） | 支持 `0x`；空=SDK `MagicDefault`（拒绝 ASCII 字面） |
| `icmp_custom_public_key` | 服务端 Noise 静态公钥 | hex(64)/base64；空=仅 PSK |
| `icmp_custom_mtu_mode` | MTU 模式 | `""`/`probe`(默认)、`auto`、`fixed` |
| `icmp_custom_max_payload` | 完整记录上限 | `0`=SDK 默认 |
| `icmp_custom_pace_ms` | 出站发包间隔 | `0`=SDK 默认 |
| `icmp_custom_id_range` | echo identifier 池 | 例 `1000-1999` |

---

## 5. 枚举附录

- **`auth_type`**：`password`（密码）；其它（默认按公钥）
- **`udpgw_version`**：`badvpn`；其它/空=tun2socks 默认
- **`kcp_mode`**：`normal` / `fast`(默认) / `fast2` / `fast3`
- **`kcp_crypt`**：`null` `none` `aes-128` `aes-192` `aes` `aes-128-gcm` `sm4` `tea` `xtea` `salsa20` `blowfish` `twofish` `cast5` `3des` `xor`
- **`kcp_smuxver`**：1 / 2(默认)
- **`dns_tunnel_type`**：`txt`(默认) / `null` / `cname` / `a`
- **`dns_tunnel_servers` scheme**：`udp`(默认) / `tcp://` / `tls://` / `dot://` / `https://`
- **`icmp_custom_mtu_mode`**：`probe`(默认) / `auto` / `fixed`
- **`xhttp_stream_mode`**：`auto`(默认) / `stream` / `poll`
- **`udp_custom_mtu_probe`**：`auto`(默认=开) / `on` / `off`
- **`masque_alpn`**（仅 masque）：配置面 `h3,h2`(=auto，默认) / `h3` / `h2`；映射到 SDK `""`/`h3`/`h2`
- **`h2tunnel UtlxFingerprint`**：myssh 固定 `chrome`（`HelloChrome_Auto`），仅 TCP-TLS 的 h2/grpc；不可配
- **ALPN（不可配）**：`raw`=`["h2","http/1.1"]`，`websocket`=`["http/1.1"]`，`quic`=`h3`；`alpn` 字段仅 `xhttp` 生效

---

## 6. 默认值与校验错误汇总

**回填默认（0/空时）：**
- kcptun：`mode`→fast、`data_shards`10、`parity_shards`3、`sndwnd`128、`rcvwnd`512、`mtu`1350、`smuxver`2、`keepalive`10
- udp_custom：`paths`32、`sockets`1、`send_window`256、`max_pkt`→1450、`mtu_probe` 空→开、`magic`→`UDPC`
- icmp_custom：`mtu_mode`→probe、`max_payload`/`pace_ms`→SDK 默认、`magic`→SDK `MagicDefault`（地址族非可配项，SDK 按对端自动选族）
- xhttp：`chunk_size_kb` 0→256、`stream_mode` 空→auto
- h2 家族：`heartbeat_interval_ms` 0→25000ms、`padding_min_bytes` 0→1420（myssh 覆写 SDK 的 900；负数关闭）、`masque_alpn` 空→auto

**建连前即拒绝（硬错误）：**
- `ssh_addr` 为空（自拨类）
- `heartbeat_interval_ms < 0`（h2 家族）
- `proxy_auth_required=true` 但对应凭据为空（h2 token / xhttp token）
- `xhttp_chunk_size_kb < 0` 或 `> 900`
- `xhttp_stream_mode` 非法值
- `kcp_mtu` 非法（`SetMtu` 返回 false）
- `udp_custom_max_pkt < 0`（`udp_custom_mtu_probe` 非 auto/on/off 时亦报错）
- TLS 且 `verify_certificate_finger_print=true` 但 `server_certificate_finger_print` 为空（含 xhttp 的 fail-closed 预检）

**仅告警（Warn，不阻断）：**
- `udp_custom_psk`/`dns_tunnel_psk`/`icmp_custom_psk` 短于 16 字符（在线爆破风险）
- xhttp HTTPS 但未配置指纹（MITM 风险，SDK 侧）

---

## 7. Web / DB 持久化说明

- 配置以 JSON key（本文）为权威；web 的 `profiles` 表用 **camelCase 列名**，经 `ToProxyConfig` 映射回 `ProxyConfig`，二者一一对应（如 `sshAddr↔ssh_addr`、`verifyCertFingerprint↔verify_certificate_finger_print`、`tunnelTLSEnabled↔tunnel_tls_enabled`）。
- schema 内默认：`udpCustomSockets DEFAULT 1`、`udpCustomSendWindow DEFAULT 256`、`xhttpChunkSizeKB DEFAULT 256`、`heartbeatIntervalMs DEFAULT 25000`。
- `tunnelTLSEnabled` 列为**可空**：历史行 `NULL` 按 `false` 解释（无旧配置兼容诉求，旧配置视为无效）。
- 以下 web 列属于 **UI/路由/统计**，不进入 `ProxyConfig`（非协议参数）：`name`、`enableCustomPath`（是否启用自定义路径的 UI 开关）、`type`、`dnsOverride`/`remoteDns`/`localDns`（覆盖 `GlobalConfig` 的 DNS）、`routingOverride`/`geositeDirect`/`geoipDirect`（分流）、`totalTx`/`totalRx`（统计）。
- `GlobalConfig` 全局字段（`local_dns_server`、`remote_dns_server`、`geosite_filepath`、`geoip_filepath`、`direct_site_tags`、`direct_ip_tags`）与 transport 参数分离，走全局设置接口。

---

*来源：[`config.go`](../config.go)（`ProxyConfig`）、各 `tunnel_*.go` 处理器的 `cfg.*` 消费、[`tunnel_sdk.go`](../tunnel_sdk.go) 的 SDK 共享 helper、[`core.go`](../core.go)（`MakePeerCertVerifier`）、[`utils.go`](../utils.go)（`buildUTLSConfig`/`newChromeUConn`）、[`web/db.go`](../web/db.go)（列映射与 schema 默认）。*
