package myssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// sha256Hex is the digest of b in the canonical form published by
// v2ray-rules-dat's sidecar.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// startRuleCDN serves a rule payload together with its sha256 sidecar.
//
// Take variadic digests so a test can hand out a different digest on each
// successive request: the released manifest and the released object are two
// separate CDN objects, so a fetch that straddles the publish moment really can
// pair new bytes with the old digest.
//
// digest == "" means "serve 404" — modelling a sidecar that is missing,
// renamed, or otherwise unreachable.
func startRuleCDN(t *testing.T, payload []byte, digests ...string) string {
	t.Helper()
	var served int64

	mux := http.NewServeMux()
	mux.HandleFunc("/payload.dat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
	})
	mux.HandleFunc("/payload.dat.sha256sum", func(w http.ResponseWriter, r *http.Request) {
		i := int(atomic.AddInt64(&served, 1)) - 1
		if i >= len(digests) {
			i = len(digests) - 1
		}
		if i < 0 || digests[i] == "" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "%s  payload.dat\n", digests[i])
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestDownloadFile_InstallsVerifiedDigest pins the happy path: with a matching
// sidecar the new file replaces the old one and no temporary file is left
// behind. It also proves verification is not so strict that nothing passes.
func TestDownloadFile_InstallsVerifiedDigest(t *testing.T) {
	payload := buildGeoIPList(t, []string{"cn", "private", "cloudflare"})
	base := startRuleCDN(t, payload, sha256Hex(payload))

	dir := t.TempDir()
	dest := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dest, []byte("stale previous copy"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := downloadFile(base+"/payload.dat", base+"/payload.dat.sha256sum", dest); err != nil {
		t.Fatalf("a body matching its published digest must install: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("installed %d bytes, want the %d verified bytes", len(got), len(payload))
	}
	if _, err := os.Lstat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("the temporary file must not survive a completed download")
	}
}

// TestDownloadFile_KeepsPreviousCopyOnMismatch is the contract the whole change
// exists to enforce: failing the checksum never reaches the file in service,
// and the previous copy keeps answering routing decisions untouched.
//
// The rejected body here is a *valid* rule file, so neither the length check
// nor the structural check can see the problem — only the digest can. This
// models the failure that motivated the change: a CDN edge serving a stale or
// mangled copy that still parses.
func TestDownloadFile_KeepsPreviousCopyOnMismatch(t *testing.T) {
	payload := buildGeoIPList(t, []string{"cn", "private", "cloudflare"})
	previous := buildGeoIPList(t, []string{"cn"}) // distinct bytes from payload
	if bytes.Equal(payload, previous) {
		t.Fatal("test fixtures must differ, otherwise the assertion below is vacuous")
	}

	// Real bytes, wrong promise. Two serves: the retry also gets the bad digest,
	// so this pins that retrying does not eventually let a bad file through.
	wrong := strings.Repeat("a", 64)
	base := startRuleCDN(t, payload, wrong, wrong)

	dir := t.TempDir()
	dest := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dest, previous, 0o644); err != nil {
		t.Fatal(err)
	}

	err := downloadFile(base+"/payload.dat", base+"/payload.dat.sha256sum", dest)
	if err == nil {
		t.Fatal("a digest mismatch must be rejected")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("the failure must name the cause, got: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("the previous copy must survive a rejected download: %v", err)
	}
	if !bytes.Equal(got, previous) {
		t.Fatal("the previous copy was replaced despite the mismatch")
	}
	if _, err := os.Lstat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("a rejected download must not leave its temporary file behind")
	}
}

// TestDownloadFile_RecoversFromCDNRollover models the benign mismatch: the
// first sidecar read lands on the digest of the edition already being replaced
// while the payload is the new one. Re-reading both resolves it, so a routine
// daily refresh must not fail just because it ran during publish.
func TestDownloadFile_RecoversFromCDNRollover(t *testing.T) {
	payload := buildGeoIPList(t, []string{"cn", "private", "cloudflare"})
	oldEdition := buildGeoIPList(t, []string{"cn"})
	if bytes.Equal(payload, oldEdition) {
		t.Fatal("test fixtures must differ, otherwise the rollover never conflicts")
	}

	good := sha256Hex(payload)
	stale := sha256Hex(oldEdition)
	base := startRuleCDN(t, payload, stale, good)

	dest := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(dest, oldEdition, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := downloadFile(base+"/payload.dat", base+"/payload.dat.sha256sum", dest); err != nil {
		t.Fatalf("a rollover must be retried past, not failed: %v", err)
	}
	if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("the payload must install once the digest catches up")
	}
}

// TestDownloadFile_FallsBackWhenSidecarMissing pins the deliberate degradation:
// an unreachable sidecar must not permanently freeze updates. The body is still
// vetted by length and structure, exactly as it was before this change existed.
func TestDownloadFile_FallsBackWhenSidecarMissing(t *testing.T) {
	payload := buildGeoIPList(t, []string{"cn", "private", "cloudflare"})
	base := startRuleCDN(t, payload) // no digests at all: sidecar 404s

	dest := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(dest, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := downloadFile(base+"/payload.dat", base+"/payload.dat.sha256sum", dest); err != nil {
		t.Fatalf("a missing sidecar must degrade to the length and structural checks: %v", err)
	}
	if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("a valid body must still install without a sidecar")
	}
}

// TestDownloadRuleFiles_WiresSidecarThrough proves DownloadRuleFiles actually
// forwards each source's sidecar URL. Everything above calls downloadFile
// directly, so nothing else would catch the call site omitting it.
func TestDownloadRuleFiles_WiresSidecarThrough(t *testing.T) {
	payload := buildGeoIPList(t, []string{"cn", "private", "cloudflare"})
	previous := []byte("previous edition")

	newCDN := func(digest string) []ruleSource {
		base := startRuleCDN(t, payload, digest)
		return []ruleSource{{
			name:   "geoip.dat",
			url:    base + "/payload.dat",
			sumURL: base + "/payload.dat.sha256sum",
		}}
	}

	t.Run("verified new edition replaces the old one", func(t *testing.T) {
		setRuleSourcesWithSum(t, newCDN(sha256Hex(payload))...)

		dir := t.TempDir()
		dest := filepath.Join(dir, "geoip.dat")
		if err := os.WriteFile(dest, previous, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := DownloadRuleFiles(dir); err != nil {
			t.Fatalf("a verified edition must be adopted: %v", err)
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, payload) {
			t.Fatal("the verified edition must replace the previous copy")
		}
	})

	t.Run("mismatched edition leaves the previous copy serving", func(t *testing.T) {
		setRuleSourcesWithSum(t, newCDN(strings.Repeat("b", 64))...)

		dir := t.TempDir()
		dest := filepath.Join(dir, "geoip.dat")
		if err := os.WriteFile(dest, previous, 0o644); err != nil {
			t.Fatal(err)
		}

		if err := DownloadRuleFiles(dir); err == nil {
			t.Fatal("a mismatched edition must be reported as a failure")
		}
		got, err := os.ReadFile(dest)
		if err != nil {
			t.Fatalf("the previous copy must survive: %v", err)
		}
		if !bytes.Equal(got, previous) {
			t.Fatal("a mismatched edition must not be written over the copy in service")
		}
	})
}

// TestParseSHA256Sum covers the shapes the sidecar may take. Anything that is
// not a bare 64-character digest must be rejected rather than silently turned
// into a comparison that always fails.
func TestParseSHA256Sum(t *testing.T) {
	const good = "391b522361c52804e486a98b53d97f3d9c1d3e4e4217bb34954774a0b456b9fd"

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"sha256sum output", good + "  geoip.dat\n", good},
		{"bare digest", good + "\n", good},
		{"no trailing newline", good + "  geoip.dat", good},
		{"uppercase digest", strings.ToUpper(good) + "  geoip.dat\n", good},
		{"blank lines first", "\n\n" + good + "  geoip.dat\n", good},
		{"filename containing spaces", good + "  some rule file.dat\n", good},
		{"empty body", "", ""},
		{"html error page", "<!DOCTYPE html><html>404 Not Found</html>", ""},
		{"too short", good[:63] + "  geoip.dat\n", ""},
		{"too long", good + "aa  geoip.dat\n", ""},
		{"non-hex", strings.Repeat("z", 64) + "  geoip.dat\n", ""},
		{"only whitespace", "   \n", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSHA256Sum(tc.in); got != tc.want {
				t.Fatalf("parseSHA256Sum(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDownloadFile_NoOverallTimeout pins the point of dropping the blanket
// Client.Timeout: a body that stays alive but streams slowly must not be killed
// mid-transfer on a weak link. The header is flushed immediately so the 30s
// ResponseHeaderTimeout never fires; only the bytes matter, and io.Copy waits
// for them.
//
// The stall (12s) deliberately exceeds the old 10s ceiling, so this also serves
// as a regression guard: revert the download client to Timeout: 10s and the test
// fails — that is exactly the failure mode this change retires.
func TestDownloadFile_NoOverallTimeout(t *testing.T) {
	payload := buildGeoIPList(t, []string{"cn", "private", "cloudflare"})
	base := startRuleCDN(t, payload, sha256Hex(payload))

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // push the header out now, before the stall
		}
		time.Sleep(12 * time.Second)
		w.Write(payload)
	}))
	defer slow.Close()

	dest := filepath.Join(t.TempDir(), "geoip.dat")
	if err := os.WriteFile(dest, []byte("stale previous copy"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := downloadFile(slow.URL, base+"/payload.dat.sha256sum", dest); err != nil {
		t.Fatalf("a slow-but-alive body must not be killed by an overall timeout: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("the slow body must still install once it arrives")
	}
}
