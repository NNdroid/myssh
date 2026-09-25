package myssh

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// GEOIP_URL / GEOSITE_URL 是规则文件的默认下载源。
const (
	GEOIP_URL   = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat"
	GEOSITE_URL = "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
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
	for _, f := range []struct {
		name string
		url  string
	}{
		{name: "geoip.dat", url: GEOIP_URL},
		{name: "geosite.dat", url: GEOSITE_URL},
	} {
		path := filepath.Join(destDir, f.name)
		if !shouldDownload(path) {
			zlog.Debugf("%s is up to date, skipping download.", f.name)
			continue
		}

		zlog.Debugf("Downloading %s...", f.name)
		if err := downloadFile(f.url, path); err != nil {
			zlog.Warnf("%s download failed, previous copy kept: %v", f.name, err)
			errs = append(errs, fmt.Errorf("failed to download %s: %w", f.name, err))
			continue
		}
		zlog.Debugf("%s downloaded and updated successfully!", f.name)
	}

	return errors.Join(errs...)
}

// downloadFile contains the core download logic: download to a temporary file first,
// then overwrite the original file upon success.
//
// The bytes are validated before the rename. jsdelivr (or any middlebox in front
// of it) can answer HTTP 200 and simply stop sending before the file is
// complete, and io.Copy reports that as success. Left unchecked, a truncated
// rule file lands on disk and LoadGeoIP later fails with the misleading
// "no specified tags found" — the reported failure mode was intermittent
// because it depended on how far the transfer got cut off.
func downloadFile(url string, destPath string) error {
	client := &http.Client{Timeout: 10 * time.Second}
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
	written, err := io.Copy(out, resp.Body)

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

	// Download is complete and successful. Rename the temporary file to the target file.
	// This operation automatically overwrites any existing file with the same name.
	zlog.Debugf("Renaming temporary file to target path: %s", destPath)
	if err := os.Rename(tempPath, destPath); err != nil {
		// Clean up the temp file if the rename operation fails
		os.Remove(tempPath)
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}
