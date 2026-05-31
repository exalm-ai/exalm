package ssh

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	gocrypto "golang.org/x/crypto/ssh"
)

// knownHostsPathOverride is used by tests to redirect the known_hosts file to
// a temporary directory. Empty string means "use the real path".
var knownHostsPathOverride string

// khMu serialises writes to the known_hosts file across goroutines.
var khMu sync.Mutex

// knownHostsPath returns the path to ~/.exalm/known_hosts, creating the
// directory if it does not exist. If knownHostsPathOverride is non-empty it
// is returned directly (no directory creation attempt is made since tests
// provide an existing temp dir).
func knownHostsPath() (string, error) {
	if knownHostsPathOverride != "" {
		return knownHostsPathOverride, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("known_hosts: resolve home dir: %w", err)
	}

	dir := filepath.Join(home, ".exalm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("known_hosts: create directory %s: %w", dir, err)
	}

	return filepath.Join(dir, "known_hosts"), nil
}

// fingerprint returns the SHA-256 fingerprint of key, base64-encoded (no
// prefix). The value is deterministic for a given key type and public key
// material.
func fingerprint(key gocrypto.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return base64.StdEncoding.EncodeToString(h[:])
}

// loadKnownHosts reads the known_hosts file and returns a map from
// "host:port" to fingerprint. If the file does not exist an empty map is
// returned without error.
func loadKnownHosts(path string) (map[string]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the known_hosts file from internal config
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("known_hosts: open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	hosts := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue // skip malformed lines
		}
		hosts[parts[0]] = parts[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("known_hosts: read %s: %w", path, err)
	}
	return hosts, nil
}

// appendKnownHost appends a new "host:port fingerprint" entry to the file at
// path, creating the file if necessary. khMu must be held by the caller.
func appendKnownHost(path, hostPort, fp string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is the known_hosts file from internal config
	if err != nil {
		return fmt.Errorf("known_hosts: open for append %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	if _, err := fmt.Fprintf(f, "%s %s\n", hostPort, fp); err != nil {
		return fmt.Errorf("known_hosts: write entry: %w", err)
	}
	return nil
}

// TOFUCallback returns a HostKeyCallback implementing trust-on-first-use
// host-key verification backed by ~/.exalm/known_hosts.
//
// Behaviour:
//   - First connection to a host: the key fingerprint is persisted and the
//     connection proceeds.
//   - Subsequent connections: the stored fingerprint is compared; a mismatch
//     returns an error explaining how to recover.
//   - If strict is true, connections to unknown hosts are rejected outright
//     instead of being auto-accepted.
func TOFUCallback(strict bool) (gocrypto.HostKeyCallback, error) {
	path, err := knownHostsPath()
	if err != nil {
		return nil, err
	}

	return func(hostname string, remote net.Addr, key gocrypto.PublicKey) error {
		// Normalise to "host:port" so the map key is canonical.
		host, port, err := net.SplitHostPort(hostname)
		if err != nil {
			// hostname has no port — use as-is with default port.
			host = hostname
			port = "22"
		}
		hostPort := net.JoinHostPort(host, port)

		fp := fingerprint(key)

		khMu.Lock()
		defer khMu.Unlock()

		known, err := loadKnownHosts(path)
		if err != nil {
			return err
		}

		stored, exists := known[hostPort]
		switch {
		case exists && stored == fp:
			// Known and matches — allow.
			return nil

		case exists && stored != fp:
			// Known but different key — possible MITM.
			return fmt.Errorf(
				"ssh: host key mismatch for %s: previously seen %s, now presenting %s. "+
					"If the host was re-provisioned, delete the entry from ~/.exalm/known_hosts",
				host, stored, fp,
			)

		case !exists && strict:
			// Unknown and strict mode — reject.
			return fmt.Errorf(
				"ssh: unknown host %s — use --no-ssh-strict-host-key to auto-accept on first connection",
				host,
			)

		default:
			// Unknown, non-strict — TOFU: persist and allow.
			if err := appendKnownHost(path, hostPort, fp); err != nil {
				return err
			}
			return nil
		}
	}, nil
}
