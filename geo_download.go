package myssh

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GEOIP_URL / GEOSITE_URL 是规则文件的默认下载源。
//
// GEOIP_SHA256_URL / GEOSITE_SHA256_URL 指向同一 release 分支里随文件一起发布
// 的摘要 sidecar（GNU coreutils 格式："<64 位十六进制>  <文件名>"）。规则重建
// 时两者一同更新，因此它是判断一次下载是否完整可信的唯一权威依据。
const (
	GEOIP_URL   = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
	GEOSITE_URL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"

	GEOIP_SHA256_URL   = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat.sha256sum"
	GEOSITE_SHA256_URL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat.sha256sum"
)

// shouldDownload reports whether filePath needs to be (re)downloaded: it is
// missing, older than 24 hours, or structurally unusable.
//
// The age check alone is not enough. A truncated download lands with a fresh
// mtime, so it would otherwise sit on disk for a full refresh cycle and keep
// breaking every LoadGeoSite/LoadGeoIP in between.
func shouldDownload(filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return true // File does not exist or cannot be accessed
	}
	if time.Since(info.ModTime()) > 24*time.Hour {
		return true
	}
	if info.Size() == 0 {
		return true
	}
	// Reuse the tag scanner as a structural check: a file whose top-level wire
	// stream stops early is truncated or not a rule file at all, either way it
	// is unusable.
	if _, truncated, err := extractGeoFileTags(filePath); err != nil || truncated {
		return true
	}
	return false
}

// ruleSource describes one rule file to fetch: where the payload lives and
// where its authoritative sha256 sidecar lives. sumURL may be empty, in which
// case the download falls back to the length and structural checks alone.
type ruleSource struct {
	name   string
	url    string
	sumURL string
}

// ruleSources lists the rule files DownloadRuleFiles fetches. It is a package
// variable rather than an inline literal so tests can redirect the URLs to an
// httptest server — a unit test must never reach the real CDN.
var ruleSources = []ruleSource{
	{name: "geoip.dat", url: GEOIP_URL, sumURL: GEOIP_SHA256_URL},
	{name: "geosite.dat", url: GEOSITE_URL, sumURL: GEOSITE_SHA256_URL},
}

// DownloadRuleFiles downloads geoip.dat and geosite.dat to the specified directory.
//
// The two files are refreshed independently: a failure on one must not strand
// the other on a stale copy, and both failures are reported.
func DownloadRuleFiles(destDir string) error {
	// Check and create the destination directory (MkdirAll returns nil if it already exists).
	// 0755 permissions: owner has read, write, execute; others have read, execute.
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	var errs []error
	for _, f := range ruleSources {
		path := filepath.Join(destDir, f.name)
		if !shouldDownload(path) {
			zlog.Debugf("%s is up to date, skipping download.", f.name)
			continue
		}

		zlog.Debugf("Downloading %s...", f.name)
		if err := downloadFile(f.url, f.sumURL, path); err != nil {
			zlog.Warnf("%s download failed, previous copy kept: %v", f.name, err)
			errs = append(errs, fmt.Errorf("failed to download %s: %w", f.name, err))
			continue
		}
		zlog.Debugf("%s downloaded and updated successfully!", f.name)
	}

	return errors.Join(errs...)
}

// RepairRuleFile re-downloads the rule file at path when the copy on disk is
// present but structurally unusable, and reports whether a usable file exists
// afterwards.
//
// shouldDownload already knows how to spot a truncated file, but it was only
// ever called from a download entry point — the web/MCP endpoint and the daily
// GeoData worker. A file that landed corrupt between runs therefore sat
// untouched for the whole session: LoadGeoIP parsed it, filled an empty Radix
// tree, and every IP fell through to the proxy — multicast, link-local and
// LAN addresses included. The load path is where corruption first becomes
// observable, so it is the right place to repair it.
//
// An absent file is deliberately left alone: config.go already reports a missing
// rule set as graceful degradation, and downloading on every cold start would
// add network latency to boot on a device that may be offline.
func RepairRuleFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false // missing, not corrupt: the caller handles absence itself
	}
	if info.Size() != 0 {
		if _, truncated, terr := extractGeoFileTags(path); terr == nil && !truncated {
			return true // already usable
		}
	}

	zlog.Warnf("%s [GeoRules] %s is corrupt or truncated, attempting a re-download before load", TAG, path)
	if dErr := DownloadRuleFiles(filepath.Dir(filepath.Clean(path))); dErr != nil {
		zlog.Warnf("%s [GeoRules] re-download failed, keeping the broken copy: %v", TAG, dErr)
		return false
	}
	// 必须重新校验内容，不能只看 Size>0：DownloadRuleFiles 只负责 geosite.dat/geoip.dat
	// 这两个默认文件名，其它（自定义 basename）压根没被碰过——只查大小会把一份仍然
	// 损坏的旧文件当成修好了，LoadGeoIP 随后照样产出空规则集。
	if _, err2 := os.Stat(path); err2 != nil {
		zlog.Warnf("%s [GeoRules] re-download reported success but %s is missing", TAG, path)
		return false
	}
	if _, truncated, terr := extractGeoFileTags(path); terr != nil || truncated {
		zlog.Warnf("%s [GeoRules] re-download reported success but %s is still unusable: %v", TAG, path, terr)
		return false
	}
	zlog.Infof("%s [GeoRules] %s repaired by re-download", TAG, path)
	return true
}

// errChecksumMismatch marks "downloaded to completion, but the bytes are not
// the ones the sha256 sidecar promised". It is a sentinel so downloadFile can
// tell this apart from a broken transport and decide whether retrying helps.
var errChecksumMismatch = errors.New("sha256 mismatch")

// downloadMaxAttempts bounds the retries around a checksum mismatch. The one
// benign cause worth retrying is a CDN rollover landing mid-flight: the
// sidecar and the payload are separate objects, so a fetch straddling the
// publish moment legitimately pairs new bytes with the old digest. Re-fetching
// both once steps over that window; a second mismatch is real corruption.
const downloadMaxAttempts = 2

// ruleDownloadTransport is the shared transport for rule-file fetches.
//
// Only the response-header phase has a deadline. The payload is ~26 MB and on
// a mobile or congested link the whole transfer can run well past the few
// seconds a desktop broadband connection takes; a blanket Client.Timeout would
// cut it off mid-stream, which surfaces as "download failed, keep the old file"
// and silently freezes rules. The header phase still has a bound, so a dead
// connection cannot hang in the handshake forever.
//
// The transport is cloned from http.DefaultTransport rather than built from a
// bare struct: a bare &http.Transport{} inherits no DialContext timeout, which
// would let connection setup stall indefinitely. Cloning carries over the sane
// dial / TLS / idle defaults and only overrides the header timeout.
var ruleDownloadTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = 30 * time.Second
	return t
}()

// downloadFile contains the core download logic: download to a temporary file
// first, verify it, and only then overwrite the original file.
//
// Order of operations is what makes this safe. Nothing is renamed into place
// until the bytes in the temporary file have passed every check, so any failure
// below leaves the file currently on disk untouched and still serving traffic.
// A rule file that fails to update degrades to last known good; a rule file
// that is replaced with garbage takes routing down with it.
func downloadFile(url string, sumURL string, destPath string) error {
	// Fetch the digest before the payload, not after. Reading it afterwards
	// would let a newer digest be compared against bytes fetched earlier.
	expected := fetchExpectedSHA256(sumURL)
	if expected == "" {
		// No authoritative digest available (sidecar down, 404, or misconfigured
		// source). Fall through to the length and structural checks rather than
		// refusing to ever update again — a missing manifest is not evidence
		// that the payload is bad, and the remaining checks still reject a
		// truncated or nonsensical body.
		zlog.Warnf("%s [GeoRules] no usable sha256 for %s, relying on length and structure checks only", TAG, url)
	}

	var err error
	for attempt := 1; attempt <= downloadMaxAttempts; attempt++ {
		err = downloadOnce(url, expected, destPath)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errChecksumMismatch) {
			// Transport failure, bad status, short read, not a rule file:
			// retrying immediately would just get the same answer.
			return err
		}
		if attempt < downloadMaxAttempts {
			zlog.Warnf("%s [GeoRules] %s %v; re-fetching digest and payload once in case the CDN is mid-rollover", TAG, url, err)
			expected = fetchExpectedSHA256(sumURL)
		}
	}
	return err
}

// downloadOnce performs one download attempt and validates it end to end.
//
// The bytes are checked before the rename. jsdelivr (or any middlebox in front
// of it) can answer HTTP 200 and simply stop sending before the file is
// complete, and io.Copy reports that as success. Left unchecked, a truncated
// rule file lands on disk and LoadGeoIP later fails with the misleading
// "no specified tags found" — the reported failure mode was intermittent
// because it depended on how far the transfer got cut off.
//
// expected is the lowercase hex sha256 the payload must match, or "" when no
// sidecar was reachable.
func downloadOnce(url string, expected string, destPath string) error {
	client := &http.Client{Transport: ruleDownloadTransport} // no overall timeout; see ruleDownloadTransport
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP GET request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	// Define the temporary file path
	tempPath := destPath + ".tmp"
	zlog.Debugf("Creating temporary file: %s", tempPath)

	// Create the temporary file
	out, err := os.Create(tempPath)
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}

	// Use io.Copy to write the response stream to the file.
	// This avoids loading the entire file into memory.
	//
	// TeeReader folds the digest in on the same pass, so a 16 MB rule file is
	// read once instead of being re-read from disk just to hash it.
	hasher := sha256.New()
	written, err := io.Copy(out, io.TeeReader(resp.Body, hasher))

	// Flush to stable storage. Best effort: the rename is what makes the new
	// file atomic for readers, the sync only guards against power loss.
	if serr := out.Sync(); serr != nil {
		zlog.Warnf("Failed to flush temporary file %s: %v", tempPath, serr)
	}

	// Ensure the file handle is closed regardless of whether writing succeeded.
	// Note: We cannot rely solely on 'defer out.Close()' here. On Windows,
	// os.Rename will fail if the file handle is still open.
	closeErr := out.Close()

	if err != nil {
		// If an error occurred during writing, remove the incomplete temporary file
		os.Remove(tempPath)
		return fmt.Errorf("failed to write data to temporary file: %w", err)
	}

	// Catch potential I/O flush errors during close
	if closeErr != nil {
		os.Remove(tempPath)
		return fmt.Errorf("failed to close temporary file safely: %w", closeErr)
	}

	// Short body: the server promised more bytes than it delivered.
	if resp.ContentLength > 0 && written != resp.ContentLength {
		os.Remove(tempPath)
		return fmt.Errorf("received %d of %d bytes from %s; previous copy kept", written, resp.ContentLength, url)
	}

	// Integrity check against the published digest. This is the one that catches
	// everything the length check cannot: a same-length body of wrong bytes from
	// a mangled cache node, a proxy that swapped content types, or a payload
	// assembled from two different versions.
	//
	// It must run before the rename. Once the temporary file is renamed over
	// destPath every reader picks it up immediately, so a bad file would already
	// be in service by the time we discovered it. Removing the temp file here
	// leaves the previous copy untouched and still serving traffic.
	if expected != "" {
		actual := hex.EncodeToString(hasher.Sum(nil))
		if !strings.EqualFold(actual, expected) {
			os.Remove(tempPath)
			return fmt.Errorf("%w for %s (%d bytes): got %s, want %s; previous copy kept",
				errChecksumMismatch, url, written, actual, expected)
		}
		zlog.Debugf("%s [GeoRules] sha256 verified for %s: %s", TAG, url, actual)
	}

	// Structural check: the top-level wire stream must run to EOF and carry at
	// least one tagged entry. This also rejects a CDN error page served as 200.
	tags, truncated, verr := extractGeoFileTags(tempPath)
	if verr != nil {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded file is not a readable rule file: %w", verr)
	}
	if truncated {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded file is truncated (%d bytes, %d entries before EOF); previous copy kept", written, len(tags))
	}
	if len(tags) == 0 {
		os.Remove(tempPath)
		return fmt.Errorf("downloaded file contains no rule entries; previous copy kept")
	}

	// Download is complete, verified, and successful. Rename the temporary file
	// to the target file. This operation automatically overwrites any existing
	// file with the same name.
	zlog.Debugf("Renaming temporary file to target path: %s", destPath)
	if err := os.Rename(tempPath, destPath); err != nil {
		// Clean up the temp file if the rename operation fails
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}

// fetchExpectedSHA256 reads the published digest for a rule file.
//
// It returns "" when the sidecar is unreachable or unparseable rather than an
// error, because a missing manifest is not itself proof that the payload is
// bad. Every caller falls back to the length and structural checks in that
// case, which keeps a broken or renamed sidecar from permanently freezing
// updates. A digest that is present is always compared strictly.
func fetchExpectedSHA256(sumURL string) string {
	if sumURL == "" {
		return ""
	}
	// The sidecar is tens of bytes; give it its own short-lived client so its
	// failure can never eat into the payload's download budget.
	client := &http.Client{Transport: ruleDownloadTransport} // no overall timeout; see ruleDownloadTransport
	resp, err := client.Get(sumURL)
	if err != nil {
		zlog.Warnf("%s [GeoRules] sha256 sidecar unreachable (%s): %v", TAG, sumURL, err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		zlog.Warnf("%s [GeoRules] sha256 sidecar returned HTTP %d (%s)", TAG, resp.StatusCode, sumURL)
		return ""
	}

	// Guard against being handed something that is obviously not a digest file:
	// an HTML error page or a redirect target would otherwise be parsed as one.
	// 4 KiB is ~50 times more than the longest plausible line.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		zlog.Warnf("%s [GeoRules] failed to read sha256 sidecar (%s): %v", TAG, sumURL, err)
		return ""
	}

	if sum := parseSHA256Sum(string(body)); sum != "" {
		return sum
	}
	zlog.Warnf("%s [GeoRules] sha256 sidecar held no usable digest: %q", TAG, string(body))
	return ""
}

// parseSHA256Sum extracts the first 64-character hex digest from a sha256sum
// manifest.
//
// It accepts both shapes seen in the wild — "<digest>  <filename>" as produced
// by GNU coreutils and published by v2ray-rules-dat, and a bare digest with no
// filename — and is deliberately tolerant of surrounding whitespace, a trailing
// newline, and either letter case. It returns "" for anything else.
func parseSHA256Sum(text string) string {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		candidate := strings.ToLower(fields[0])
		if len(candidate) != 64 {
			continue
		}
		if _, err := hex.DecodeString(candidate); err != nil {
			continue
		}
		return candidate
	}
	return ""
}
