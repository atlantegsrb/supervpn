package update

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	releasesRepo = "atlanteg/supervpn-releases"
	githubAPIURL = "https://api.github.com/repos/" + releasesRepo + "/releases/latest"
	// githubDLBase uses the tag-specific URL (not /latest/download/) to avoid
	// CDN caching lag where the API returns a new tag but the CDN still serves
	// the previous binary, causing an infinite update-restart loop.
	githubDLBase = "https://github.com/" + releasesRepo + "/releases/download/"
)

// relaunchEnv marks a process spawned by the self-updater's reexec.
const relaunchEnv = "SUPERVPN_RELAUNCHED"

// RelaunchedByUpdate reports whether this process was started by a self-update
// restart. Such a process must NOT run CheckAndUpdate again (avoids re-exec
// chains on CDN lag) and, in the GUI, must NOT defer to an existing instance —
// it is the legitimate successor while the old process is still exiting.
func RelaunchedByUpdate() bool { return os.Getenv(relaunchEnv) == "1" }

// knownServerIPs lists all known supervpn server IPs that run the update
// mirror on port 80 at /update. Used as fallback when GitHub is unreachable.
var knownServerIPs = []string{
	"81.27.241.25",
	"185.108.16.16",
	"212.48.224.5",
	"162.55.48.218",
	"49.13.4.85",
}

// mirrorPorts lists the ports the update mirror is served on. 993 (IMAPS) —
// privileged, near-universally firewall-allowed, rarely DPI-filtered, and free
// of the nginx-on-:80 conflict. (Kept as a slice for easy future additions.)
var mirrorPorts = []string{"993"}

// DefaultMirrors returns the known server mirror base URLs in RANDOM order.
// Each server exposes GET /update/version and GET /update/{asset} on each of
// mirrorPorts. Clients use these as fallback when GitHub is unreachable. The
// order is shuffled on every call (i.e. every launch) so clients try a
// different mirror first each time — spreading load across servers and avoiding
// always hitting (or being blocked on) the same one. Go 1.20+ auto-seeds the
// global rand source, so no explicit Seed is needed.
func DefaultMirrors() []string {
	m := make([]string, 0, len(knownServerIPs)*len(mirrorPorts))
	for _, ip := range knownServerIPs {
		for _, port := range mirrorPorts {
			m = append(m, "http://"+ip+":"+port+"/update")
		}
	}
	rand.Shuffle(len(m), func(i, j int) { m[i], m[j] = m[j], m[i] })
	return m
}

// CheckAndUpdate checks for a newer release using GitHub and optional mirror
// base URLs (each mirror must serve GET {base}/version → plain-text "bN",
// and GET {base}/{asset} → binary). Tries each source in order; first success
// wins for both version check and download. Does not return on success.
func CheckAndUpdate(currentVersion, asset string, mirrors []string) {
	cur, err := parseVersion(currentVersion)
	if err != nil {
		log.Printf("update: dev build — skipping version check")
		return
	}

	log.Printf("update: checking for updates (current: %s) ...", currentVersion)

	ghc := &http.Client{Timeout: 10 * time.Second}
	mc := mirrorHTTPClient(15 * time.Second)

	tag, tagSrc, err := resolveLatestTag(ghc, mc, mirrors)
	if err != nil {
		log.Printf("update: check failed (current: %s, all sources unreachable): %v", currentVersion, err)
		return
	}

	latest, err := parseVersion(tag)
	if err != nil {
		return
	}
	if latest <= cur {
		log.Printf("update: up to date (%s is latest)", currentVersion)
		return
	}

	log.Printf("update: new version %s available (via %s) — downloading %s ...", tag, tagSrc, asset)

	exe, err := os.Executable()
	if err != nil {
		log.Printf("update: cannot locate executable: %v", err)
		return
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		log.Printf("update: eval symlinks: %v", err)
		return
	}

	ghDL := &http.Client{Timeout: 3 * time.Minute}
	// Peer-mirror links can be much slower than GitHub's CDN; the binary is
	// ~15 MB, so give the body read a generous total budget (a dead mirror still
	// fails fast at the 8 s dial/TLS stage, so this only extends genuinely
	// reachable-but-slow mirrors). 2 min was too tight and timed out mid-download.
	mcDL := mirrorHTTPClient(8 * time.Minute)
	if err := downloadWithFallback(ghDL, mcDL, tag, asset, exe, mirrors); err != nil {
		if errors.Is(err, errBinaryUnchanged) {
			log.Printf("update: %s asset is identical to current binary — already up to date (tag reused)", tag)
			return
		}
		log.Printf("update: download failed (all sources): %v", err)
		return
	}

	log.Printf("update: updated to %s — restarting", tag)
	reexec(exe)
}

// mirrorHTTPClient builds an HTTP client for the hardcoded peer-server mirror IPs.
// It (a) accepts self-signed / IP-only TLS certs — a mirror may redirect http→https
// and an IP host has no cert SAN, which otherwise fails verification — and (b) uses
// short dial/handshake timeouts so an unreachable mirror fails in seconds and the
// next one is tried. This adds no exposure beyond the design's existing plaintext
// HTTP mirror fetch: the IP list is hardcoded and the transport was already
// untrusted (binaries are not signed). knownServerIPs is the trust anchor.
func mirrorHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DialContext:         (&net.Dialer{Timeout: 8 * time.Second}).DialContext,
			TLSHandshakeTimeout: 8 * time.Second,
		},
	}
}

// resolveLatestTag tries GitHub API first, then each mirror's /version endpoint.
// Returns the tag, the source label, and any error if all sources failed.
func resolveLatestTag(ghc, mc *http.Client, mirrors []string) (tag, src string, err error) {
	// GitHub API
	if t, e := latestTagFromGitHub(ghc); e == nil {
		return t, "github", nil
	} else {
		err = e
	}

	// Mirrors: GET {base}/version → plain text "bN"
	for _, m := range mirrors {
		url := strings.TrimRight(m, "/") + "/version"
		if t, e := latestTagFromURL(mc, url); e == nil {
			return t, m, nil
		}
	}

	// Last resort: resolve the version in-band over Reality (HTTP fully blocked).
	if t, e := latestTagInBand(); e == nil {
		return t, "reality", nil
	}

	return "", "", fmt.Errorf("github: %w; mirrors tried: %d", err, len(mirrors))
}

func latestTagFromGitHub(c *http.Client) (string, error) {
	req, _ := http.NewRequest("GET", githubAPIURL, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	if r.TagName == "" {
		return "", fmt.Errorf("empty tag_name in GitHub response")
	}
	return r.TagName, nil
}

// latestTagFromURL fetches a plain-text version string (e.g. "b101") from url.
func latestTagFromURL(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32))
	if err != nil {
		return "", err
	}
	tag := strings.TrimSpace(string(body))
	if tag == "" {
		return "", fmt.Errorf("empty version response")
	}
	return tag, nil
}

// downloadWithFallback tries GitHub (tag-specific URL) first, then each mirror.
// Returns errBinaryUnchanged if every source served an identical binary.
func downloadWithFallback(ghc, mc *http.Client, tag, asset, exe string, mirrors []string) error {
	type source struct {
		url    string
		client *http.Client
	}
	sources := []source{{githubDLBase + tag + "/" + asset, ghc}}
	for _, m := range mirrors {
		sources = append(sources, source{strings.TrimRight(m, "/") + "/" + asset, mc})
	}

	var lastErr error
	for _, s := range sources {
		if err := downloadAndReplace(s.client, s.url, exe); err != nil {
			if errors.Is(err, errBinaryUnchanged) {
				return errBinaryUnchanged
			}
			log.Printf("update: download from %s failed: %v", s.url, err)
			lastErr = err
			continue
		}
		return nil
	}

	// Last resort: the DPI-resistant in-band Reality channel. When GitHub and the
	// plain-HTTP mirrors are blocked (aggressive DPI), pull the binary from a peer
	// over the same transport that already defeats blocking.
	log.Printf("update: HTTP sources exhausted — trying in-band Reality from peers ...")
	if err := downloadInBand(asset, exe); err != nil {
		if errors.Is(err, errBinaryUnchanged) {
			return errBinaryUnchanged
		}
		log.Printf("update: in-band Reality fallback failed: %v", err)
		if lastErr == nil {
			lastErr = err
		}
		return lastErr
	}
	return nil
}

// AssetForClient returns the release asset filename for the current client platform.
func AssetForClient() string {
	switch runtime.GOOS {
	case "windows":
		return "supervpn-client-windows-amd64.exe"
	case "linux":
		if runtime.GOARCH == "arm64" {
			return "supervpn-client-linux-arm64"
		}
		return "supervpn-client-linux-amd64"
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "supervpn-client-darwin-arm64"
		}
		return "supervpn-client-darwin-amd64"
	default:
		return "supervpn-client-darwin-amd64"
	}
}

// AssetForClientGUI returns the release asset filename for the Win32/Walk GUI build.
// On Windows this is the default (Walk/GDI) variant; on macOS it is the arch-specific binary.
func AssetForClientGUI() string {
	switch {
	case runtime.GOOS == "windows" && runtime.GOARCH == "386":
		return "supervpn-client-gui-windows-386.exe"
	case runtime.GOOS == "windows":
		return "supervpn-client-gui-windows-amd64.exe"
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		return "supervpn-client-gui-darwin-arm64"
	default:
		return "supervpn-client-gui-darwin-amd64"
	}
}

// AssetForClientGUIFyne returns the release asset filename for the Fyne GUI build.
// On Windows this is the OpenGL/Fyne variant; on macOS same as AssetForClientGUI.
func AssetForClientGUIFyne() string {
	switch {
	case runtime.GOOS == "windows":
		return "supervpn-client-gui-windows-fyne-amd64.exe"
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		return "supervpn-client-gui-darwin-arm64"
	default:
		return "supervpn-client-gui-darwin-amd64"
	}
}

// AssetForSeema returns the release asset filename for the seema pre-configured client.
func AssetForSeema() string {
	return "supervpn-seema-windows-amd64.exe"
}

// AssetForBMGarage returns the release asset filename for the bmgarage
// pre-configured client.
func AssetForBMGarage() string {
	return "supervpn-bmgarage-windows-amd64.exe"
}

const AssetServer = "supervpn-server"

// FetchAsset downloads one release asset from the tag-specific GitHub URL to
// destPath, creating parent directories as needed. Written atomically via a
// .new temp file. Intended for servers pre-populating their mirror directory.
func FetchAsset(tag, asset, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	c := &http.Client{Timeout: 3 * time.Minute}
	return downloadAndReplace(c, githubDLBase+tag+"/"+asset, destPath)
}

// CleanupOldFiles removes any *.old files sitting next to the running
// executable — leftovers from a previous Windows self-update where the old
// binary is renamed to .old before the new one is placed.  Safe to call on
// every startup; silently skips files it cannot remove (e.g. still locked).
func CleanupOldFiles() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	// The .old file is the previous binary, which Windows keeps locked until the
	// pre-update process fully exits — and that can lag this (successor) process's
	// startup by a moment, so a single Remove attempt at launch often failed and
	// left the .old orphaned next to the exe. Retry in the background.
	go func() {
		for i := 0; i < 30; i++ {
			matches, _ := filepath.Glob(filepath.Join(dir, "*.old"))
			remaining := 0
			for _, f := range matches {
				if err := os.Remove(f); err != nil {
					remaining++
				} else {
					log.Printf("update: removed stale backup %s", filepath.Base(f))
				}
			}
			if remaining == 0 {
				return
			}
			time.Sleep(time.Second)
		}
	}()
}

func parseVersion(v string) (int, error) {
	return strconv.Atoi(strings.TrimPrefix(v, "b"))
}

// errBinaryUnchanged is returned by downloadAndReplace when the downloaded
// binary is byte-for-byte identical to the currently running one.  This
// happens when a release tag is published with an asset that was filled from
// a previous release (e.g. build was skipped).  Callers must not treat this
// as a real error and must not re-exec.
var errBinaryUnchanged = errors.New("downloaded binary is identical to current — skipping replace")

func downloadAndReplace(c *http.Client, url, exe string) error {
	resp, err := c.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return applyBinary(resp.Body, exe)
}

// applyBinary atomically replaces exe with the bytes from r (via exe.new). It
// returns errBinaryUnchanged when the new binary is byte-identical to the
// running one (so the caller doesn't re-exec into the same binary forever), and
// on Windows renames the current exe to .old first. Shared by the HTTP and the
// in-band Reality download paths.
func applyBinary(r io.Reader, exe string) error {
	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}

	if same, _ := filesBytesEqual(exe, tmp); same {
		os.Remove(tmp)
		return errBinaryUnchanged
	}

	if runtime.GOOS == "windows" {
		old := exe + ".old"
		os.Remove(old)
		if err := os.Rename(exe, old); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("rename current→.old: %w", err)
		}
	}
	if err := os.Rename(tmp, exe); err != nil {
		return fmt.Errorf("rename .new→current: %w", err)
	}
	return nil
}

// filesBytesEqual returns true when both files exist and have identical content.
func filesBytesEqual(a, b string) (bool, error) {
	ab, err := os.ReadFile(a)
	if err != nil {
		return false, err
	}
	bb, err := os.ReadFile(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(ab, bb), nil
}
