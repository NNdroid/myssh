package myssh

import (
	"testing"
)

// TestFormatSHA256FingerprintKnownVector pins the exact wire format of the
// fingerprint. It is compared (after normalization) against the configured pin,
// so any drift in casing or separators silently breaks cert pinning — this is
// the guard for that. Expected value is SHA-256 of the empty input.
func TestFormatSHA256FingerprintKnownVector(t *testing.T) {
	const want = "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:" +
		"27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"

	got := formatSHA256Fingerprint(nil)
	if got != want {
		t.Fatalf("fingerprint format drifted:\n got: %s\nwant: %s", got, want)
	}
	if len(got) != 95 { // 32 bytes -> "XX" + 31 separators
		t.Fatalf("expected 95 chars, got %d", len(got))
	}
}

// BenchmarkFormatSHA256Fingerprint guards the hot-path cost: certificate
// verification builds the fingerprint unconditionally on every TLS/QUIC
// handshake (it is logged even when pinning is off), so this must stay
// allocation-light rather than going through fmt per byte.
func BenchmarkFormatSHA256Fingerprint(b *testing.B) {
	raw := make([]byte, 1024)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = formatSHA256Fingerprint(raw)
	}
}
