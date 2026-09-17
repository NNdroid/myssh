package myssh

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// buildGeoList serializes a rule file that is nothing but repeated entries: no
// trailing fields. buildGeoList(tags[:n-1]) is therefore an exact byte prefix
// of buildGeoList(tags), which is what lets a cut at the entry boundary
// simulate an interrupted download precisely.
func buildGeoList(t *testing.T, tags []string) []byte {
	t.Helper()
	var buf []byte
	for _, tag := range tags {
		// A domain/cidr-shaped payload so both parsers exercise their skip path.
		payload := protowire.AppendTag(nil, 1, protowire.VarintType)
		payload = protowire.AppendVarint(payload, 2)
		payload = protowire.AppendTag(payload, 2, protowire.BytesType)
		payload = protowire.AppendString(payload, "example-"+tag+".com")

		entry := protowire.AppendTag(nil, 1, protowire.BytesType)
		entry = protowire.AppendString(entry, tag)
		entry = protowire.AppendTag(entry, 2, protowire.BytesType)
		entry = protowire.AppendBytes(entry, payload)

		buf = protowire.AppendTag(buf, 1, protowire.BytesType)
		buf = protowire.AppendBytes(buf, entry)
	}
	return buf
}

// splitGeoFixture serializes a rule file with the given tags and reports the
// byte offset where the final entry begins. Cutting just past that offset
// reproduces what an interrupted download looks like on disk: every entry up to
// the last one is intact and the last one is unreadable.
func splitGeoFixture(t *testing.T, tags []string) (full []byte, lastEntryOffset int) {
	t.Helper()
	full = buildGeoList(t, tags)
	return full, len(buildGeoList(t, tags[:len(tags)-1]))
}

// writeCutGeoFile writes a rule file holding one unrelated tag followed by
// every requested tag, then cuts off mid-entry right after that prefix. Every
// requested tag therefore sits past the cut, which is the shape that used to
// report the misleading "no specified tags found" error.
func writeCutGeoFile(t *testing.T, requested []string) string {
	t.Helper()
	prefix := buildGeoList(t, []string{"unrelated"})
	full := buildGeoList(t, append([]string{"unrelated"}, requested...))

	return writeRuleFile(t, "rule.dat", full[:len(prefix)+3])
}

// writeRuleFile writes data to a fresh temp file under a given name.
func writeRuleFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadGeoIP_TruncatedReportsTruncation is the regression for the reported
// intermittent failure: a geoip.dat that stopped before the requested tags used
// to surface as "no specified tags found", which reads like a config mistake
// and pointed nowhere. It must now name the truncated file.
func TestLoadGeoIP_TruncatedReportsTruncation(t *testing.T) {
	requested := []string{"cn", "private"}
	path := writeCutGeoFile(t, requested)

	err := newGeoRouter().LoadGeoIP(path, requested)
	if err == nil {
		t.Fatal("truncated file must not load as if it were complete")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error must name the truncated file, got: %v", err)
	}
	if strings.Contains(err.Error(), "no specified tags found") {
		t.Fatalf("misleading config error must not be reused for a truncated file: %v", err)
	}
}

// TestLoadGeoIP_NoMatchInCompleteFile guards the opposite branch: a whole file
// that genuinely lacks the requested tag must still be reported as a tag
// problem, not as corruption.
func TestLoadGeoIP_NoMatchInCompleteFile(t *testing.T) {
	full, _ := splitGeoFixture(t, []string{"private", "cloudflare"})
	path := writeRuleFile(t, "geoip.dat", full)

	err := newGeoRouter().LoadGeoIP(path, []string{"cn"})
	if err == nil {
		t.Fatal("missing tag in a complete file must still fail")
	}
	if !strings.Contains(err.Error(), "no specified tags found") {
		t.Fatalf("config error must still be reported as a tag problem, got: %v", err)
	}
	if strings.Contains(err.Error(), "truncated") {
		t.Fatalf("complete file must not be reported as truncated: %v", err)
	}
}

// TestLoadGeoIP_CompleteFileLoads verifies the happy path is untouched.
func TestLoadGeoIP_CompleteFileLoads(t *testing.T) {
	full, _ := splitGeoFixture(t, []string{"private", "cloudflare", "cn"})
	path := writeRuleFile(t, "geoip.dat", full)

	if err := newGeoRouter().LoadGeoIP(path, []string{"cn", "private"}); err != nil {
		t.Fatalf("complete file must load: %v", err)
	}
}

// TestLoadGeoIP_TruncatedKeepsPartialRules: when the requested tags already
// appeared before the cut, the partial data is usable and the load succeeds
// rather than failing closed. Availability beats an empty rule set.
func TestLoadGeoIP_TruncatedKeepsPartialRules(t *testing.T) {
	full, off := splitGeoFixture(t, []string{"cn", "private", "cloudflare"})
	path := writeRuleFile(t, "geoip.dat", full[:off+3])

	if err := newGeoRouter().LoadGeoIP(path, []string{"cn", "private"}); err != nil {
		t.Fatalf("partial but usable rules must still load: %v", err)
	}
}

func TestLoadGeoSite_TruncatedReportsTruncation(t *testing.T) {
	requested := []string{"cn", "private"}
	path := writeCutGeoFile(t, requested)

	err := newGeoRouter().LoadGeoSite(path, requested)
	if err == nil {
		t.Fatal("truncated file must not load as if it were complete")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error must name the truncated file, got: %v", err)
	}
	if strings.Contains(err.Error(), "no specified tags found") {
		t.Fatalf("misleading config error must not be reused for a truncated file: %v", err)
	}
}

func TestLoadGeoSite_NoMatchInCompleteFile(t *testing.T) {
	full, _ := splitGeoFixture(t, []string{"private", "cloudflare"})
	path := writeRuleFile(t, "geosite.dat", full)

	err := newGeoRouter().LoadGeoSite(path, []string{"cn"})
	if err == nil {
		t.Fatal("missing tag in a complete file must still fail")
	}
	if !strings.Contains(err.Error(), "no specified tags found") {
		t.Fatalf("config error must still be reported as a tag problem, got: %v", err)
	}
	if strings.Contains(err.Error(), "truncated") {
		t.Fatalf("complete file must not be reported as truncated: %v", err)
	}
}

// TestLoadGeoIP_GarbageFile covers the case where a non-rule file (for example
// a CDN error page served with HTTP 200) ends up on disk.
func TestLoadGeoIP_GarbageFile(t *testing.T) {
	path := writeRuleFile(t, "geoip.dat", bytes.Repeat([]byte{0xff}, 256))

	err := newGeoRouter().LoadGeoIP(path, []string{"cn", "private"})
	if err == nil {
		t.Fatal("non-rule file must not load as if it were complete")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("unparsable file must be reported as truncated, got: %v", err)
	}
}

// TestShouldDownload_RejectsInvalidFiles is the self-healing half of the fix:
// a corrupt file carries a fresh mtime, so the age check alone would leave it
// on disk for a full refresh cycle.
func TestShouldDownload_RejectsInvalidFiles(t *testing.T) {
	full, off := splitGeoFixture(t, []string{"private", "cloudflare", "cn"})

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "missing file", want: true},
		{name: "valid file", data: full, want: false},
		{name: "truncated file", data: full[:off+3], want: true},
		{name: "empty file", data: []byte{}, want: true},
		{name: "garbage file", data: bytes.Repeat([]byte{0xff}, 256), want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "geoip.dat")
			if tc.data != nil {
				if err := os.WriteFile(path, tc.data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := shouldDownload(path); got != tc.want {
				t.Fatalf("shouldDownload(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestDownloadFile_NeverInstallsBadBody drives downloadFile against local
// servers. In every failure case the previous copy must survive and no temp
// file may be left behind.
func TestDownloadFile_NeverInstallsBadBody(t *testing.T) {
	full, off := splitGeoFixture(t, []string{"private", "cloudflare", "cn"})
	sentinel := mustBuildGeo(t, []string{"private"})

	cases := []struct {
		name    string
		body    []byte
		declare int  // declared Content-Length; 0 = let the server decide
		drop    bool // close the connection before the body is fully sent
	}{
		{name: "connection drops mid-file", body: full[:off+3], declare: len(full), drop: true},
		{name: "server serves a short file", body: full[:off+3], declare: 0},
		{name: "cdn error page as 200", body: []byte("<!DOCTYPE html><html><body>502 Bad Gateway</body></html>"), declare: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.declare > 0 {
					w.Header().Set("Content-Length", strconv.Itoa(tc.declare))
				}
				w.WriteHeader(http.StatusOK)
				w.Write(tc.body)
				if tc.drop {
					if hj, ok := w.(http.Hijacker); ok {
						conn, buf, _ := hj.Hijack()
						buf.Flush()
						conn.Close()
					}
				}
			}))
			defer srv.Close()

			dir := t.TempDir()
			dest := filepath.Join(dir, "geoip.dat")
			if err := os.WriteFile(dest, sentinel, 0o644); err != nil {
				t.Fatal(err)
			}

			if err := downloadFile(srv.URL, dest); err == nil {
				t.Fatal("malformed body must be rejected")
			}

			got, err := os.ReadFile(dest)
			if err != nil {
				t.Fatalf("previous copy must survive: %v", err)
			}
			if !bytes.Equal(got, sentinel) {
				t.Fatalf("previous copy was clobbered (got %d bytes, want %d)", len(got), len(sentinel))
			}
			if _, err := os.Lstat(dest + ".tmp"); !os.IsNotExist(err) {
				t.Fatalf("temporary file must be cleaned up: %v", err)
			}
		})
	}
}

// TestDownloadFile_InstallsValidFile makes sure the new validation cannot
// simply block every download.
func TestDownloadFile_InstallsValidFile(t *testing.T) {
	full, _ := splitGeoFixture(t, []string{"private", "cloudflare", "cn"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(full)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "geoip.dat")

	if err := downloadFile(srv.URL, dest); err != nil {
		t.Fatalf("valid body must install: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, full) {
		t.Fatalf("installed %d bytes, want %d", len(got), len(full))
	}
	if shouldDownload(dest) {
		t.Fatal("a freshly installed valid file must not be re-downloaded")
	}
}

// TestDownloadFile_AcceptsCompleteShortFile makes sure the structural check is
// not a size check: a smaller file that still parses cleanly is a valid rule
// file and must install.
func TestDownloadFile_AcceptsCompleteShortFile(t *testing.T) {
	full, _ := splitGeoFixture(t, []string{"private", "cloudflare", "cn"})
	short, _ := splitGeoFixture(t, []string{"private", "cloudflare"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(short)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(dest, full, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := downloadFile(srv.URL, dest); err != nil {
		t.Fatalf("a complete %d-byte file must install (%d bytes available): %v", len(short), len(full), err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, short) {
		t.Fatalf("installed %d bytes, want %d", len(got), len(short))
	}
}
