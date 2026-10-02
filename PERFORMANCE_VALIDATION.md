# Throughput and stability validation

Validated on 2026-10-02, based on commit `1052e1864876c0e48f245f070a179be693731fec`.

## Changes

Engine replacement serializes Start/Stop and drains the old connection loop and
SOCKS listener. SSH handshakes and channel dials support cancellation; retry
sleep is interruptible. A nil SSH Wait result no longer panics. Keepalive tasks
end when their own SSH connection ends.

SOCKS UDP ingress now uses 16 FIFO workers with 32 queued packets each, pooled
packet storage and a larger kernel receive buffer. Session state has an idle
sweeper, a combined direct/UDPGW budget and conditional deletion, preventing old
readers from deleting replacements. Direct replies use a full datagram buffer.

TCP relays preserve half-close. Plain TCP on Linux/Android uses splice with
RawConn.Read/Write, which retain descriptor ownership and honor netpoll deadlines
and Close. Accounting is updated on each transfer; protocol wrappers are never
bypassed. Copy fallback is allowed only before any input has been consumed.

Badvpn caches destination headers and assembles a complete frame in a pooled
buffer. Both UDPGW implementations handle short writes and reject lengths that
overflow their 16-bit framing. TCP socket buffer overrides, UDP session limits
and idle timeout settings round-trip through the web UI/database and core JSON.
See README.md for defaults and ranges.

## Checks

- Windows amd64, Go 1.26.4: `go test ./...`, `go vet ./...`, `git diff --check` passed.
- Linux amd64 (ndjc-nas0): complete root-package test suite passed, including
  UDP Custom Noise/PSK interoperability with the pinned SDK's precompiled server,
  supplied through the existing `UDPC_BIN` test option. Test binaries ran in an
  isolated temporary directory.
- Linux splice, relay, UDP ingress, session lifecycle and engine stop/restart
  regressions passed 10 consecutive runs. Deadline/backpressure tests exercise
  real loopback TCP sockets; datagram tests exercise the SOCKS UDP receiver.
- Windows race checks could not compile: CGO disabled by default; enabling it
  exposed missing `windows.h` in the configured compiler. No race-clean claim.
- Android runtime/UI and real WAN/mobile throughput remain unverified.

## Benchmarks

Three 1-second runs per case, Linux amd64, Intel Celeron J1900, Go 1.26.4.
The baseline was an isolated archive of the base commit with the same framing
benchmark added. The current copy/splice cases use identical tracked connections
and 64KiB writes over two loopback TCP socket pairs.

| Case | Result range | Allocation | Underlying writes per packet |
| --- | --- | --- | --- |
| Baseline Badvpn, 1400-byte payload | 2361–2399 ns/op | 1538 B/op, 2 allocs/op | 2 |
| Optimized Badvpn, 1400-byte payload | 239.6–248.1 ns/op | 0 B/op, 0 allocs/op | 1 |
| Tracked direct relay, copy | 426.78–444.60 MB/s | 0 allocs/op | n/a |
| Tracked direct relay, splice | 732.70–763.02 MB/s | 0 allocs/op | n/a |

The framing benchmark uses a discard connection and measures assembly cost,
not network capacity. The relay benchmark measures loopback throughput, not
SSH encryption or WAN throughput. These results do not establish a production
speedup or the best socket buffer size for a particular device/path.
