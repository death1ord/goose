package config

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"goose/internal/version"
)

// Version returns the running fallow version for minimumVersion checks.
func Version() string { return version.Version }

// compareVersion compares two MAJOR.MINOR.PATCH strings. It returns
// (comparison, true) or (0, false) when either value is malformed.
func compareVersion(a, b string) (int, bool) {
	pa, ok := parseVersion(a)
	if !ok {
		return 0, false
	}
	pb, ok := parseVersion(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		if pa[i] < pb[i] {
			return -1, true
		}
		if pa[i] > pb[i] {
			return 1, true
		}
	}
	return 0, true
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func fetchURL(url string) ([]byte, error) {
	timeout := 5 * time.Second
	if raw := envOr("FALLOW_EXTENDS_TIMEOUT_SECS", ""); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
			timeout = time.Duration(secs) * time.Second
		}
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fallow: cannot fetch extends %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("fallow: extends %q returned HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return nil, fmt.Errorf("fallow: cannot read extends %q: %w", url, err)
	}
	if len(body) > 1<<20 {
		return nil, fmt.Errorf("fallow: extends %q is larger than 1 MB", url)
	}
	return body, nil
}

func envOr(key, fallback string) string {
	if v, ok := lookupEnv(key); ok {
		return v
	}
	return fallback
}
