// Package ssh provides a thin, context-aware SSH client used by log plugins
// to collect remote logs without requiring an agent on the target machine.
//
// # Security note
//
// Host-key verification uses TOFU (trust-on-first-use) backed by
// ~/.exalm/known_hosts. The first connection to a new host auto-accepts and
// persists the host key; subsequent connections verify against the stored
// fingerprint. Pass StrictHostKey: true to reject unknown hosts outright.
//
// # Authentication priority
//
//  1. Private key file (--key flag, or ~/.ssh/id_rsa by default)
//  2. SSH agent (SSH_AUTH_SOCK)
//  3. Password (EXALM_SSH_PASSWORD env var or --password flag)
package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	gocrypto "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Options configures an SSH connection.
type Options struct {
	// Host is the remote hostname or IP address (required).
	Host string
	// Port is the SSH port; defaults to 22.
	Port int
	// User is the SSH username; defaults to the current OS user.
	User string
	// KeyPath is the path to the PEM-encoded private key.
	// If empty, ~/.ssh/id_rsa is tried first, then the SSH agent.
	KeyPath string
	// Password is used when key auth is unavailable.
	// Prefer EXALM_SSH_PASSWORD env var over passing it directly.
	Password string
	// Signer is a pre-loaded crypto/ssh signer, useful in tests so no
	// key file is needed on disk. Ignored when nil.
	Signer gocrypto.Signer
	// Timeout for the initial dial; defaults to 15 s.
	Timeout time.Duration
	// StrictHostKey controls TOFU host-key verification behaviour.
	// When false (default), unknown hosts are auto-accepted and their key is
	// persisted to ~/.exalm/known_hosts on first connection.
	// When true, connections to unknown hosts are rejected outright.
	StrictHostKey bool
}

// Client wraps an active SSH connection.
type Client struct {
	c         *gocrypto.Client
	opts      Options
	agentConn io.Closer // non-nil when connected via SSH_AUTH_SOCK; closed on Close()
}

// Dial establishes an SSH connection with the given options.
// The caller is responsible for calling Close() when done.
func Dial(ctx context.Context, opts Options) (*Client, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	opts.applyDefaults()

	auth, agentConn, err := buildAuthMethods(opts)
	if err != nil {
		return nil, fmt.Errorf("ssh: auth: %w", err)
	}

	hostKeyCB, err := TOFUCallback(opts.StrictHostKey)
	if err != nil {
		return nil, fmt.Errorf("ssh: known_hosts: %w", err)
	}

	cfg := &gocrypto.ClientConfig{
		User:            opts.User,
		Auth:            auth,
		HostKeyCallback: hostKeyCB,
		Timeout:         opts.Timeout,
	}

	addr := net.JoinHostPort(opts.Host, fmt.Sprintf("%d", opts.Port))

	dialCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	nd := &net.Dialer{}
	tcpConn, err := nd.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := gocrypto.NewClientConn(tcpConn, addr, cfg)
	if err != nil {
		tcpConn.Close() //nolint:errcheck
		return nil, fmt.Errorf("ssh: handshake %s: %w", addr, err)
	}

	return &Client{
		c:         gocrypto.NewClient(sshConn, chans, reqs),
		opts:      opts,
		agentConn: agentConn,
	}, nil
}

// RunCommand executes cmd on the remote host and returns its stdout.
// The returned Reader is fully buffered; the SSH session is closed before
// this function returns, so the caller may use the Reader at leisure.
func (c *Client) RunCommand(ctx context.Context, cmd string) (io.Reader, error) {
	sess, err := c.c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh: new session: %w", err)
	}
	defer sess.Close() //nolint:errcheck

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	type result struct{ err error }
	done := make(chan result, 1)
	go func() { done <- result{sess.Run(cmd)} }()

	select {
	case <-ctx.Done():
		// Signal the remote process to terminate, then wait for the goroutine
		// to drain so stdout/stderr buffers are not written to concurrently
		// after we return. sess.Close() (deferred) will unblock sess.Run.
		sess.Signal(gocrypto.SIGTERM) //nolint:errcheck
		<-done                        // drain goroutine to prevent data race
		return nil, fmt.Errorf("ssh: command interrupted: %w", ctx.Err())
	case r := <-done:
		if r.err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return nil, fmt.Errorf("ssh: %s: %w (stderr: %s)", cmd, r.err, msg)
			}
			return nil, fmt.Errorf("ssh: %s: %w", cmd, r.err)
		}
	}

	return &stdout, nil
}

// Close closes the SSH connection and, if one was opened, the SSH agent
// socket. The first non-nil error is returned.
func (c *Client) Close() error {
	err := c.c.Close()
	if c.agentConn != nil {
		if aerr := c.agentConn.Close(); aerr != nil && err == nil {
			err = aerr
		}
	}
	return err
}

// Host returns the remote hostname this client is connected to.
func (c *Client) Host() string { return c.opts.Host }

// ─── helpers ─────────────────────────────────────────────────────────────────

func (o *Options) validate() error {
	if strings.TrimSpace(o.Host) == "" {
		return fmt.Errorf("ssh: host is required")
	}
	return nil
}

func (o *Options) applyDefaults() {
	if o.Port == 0 {
		o.Port = 22
	}
	if o.User == "" {
		if u := os.Getenv("USER"); u != "" {
			o.User = u
		} else if u := os.Getenv("USERNAME"); u != "" { // Windows
			o.User = u
		} else {
			o.User = "root"
		}
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
}

// buildAuthMethods assembles SSH authentication methods from opts.
// It returns the method list and, if an SSH agent socket was opened, the
// net.Conn to that socket. The caller must close the conn when done with
// the SSH client to avoid file-descriptor leaks.
func buildAuthMethods(opts Options) ([]gocrypto.AuthMethod, io.Closer, error) {
	var methods []gocrypto.AuthMethod
	var agentConn io.Closer

	// 0. Pre-loaded signer (used in tests, takes priority over file).
	if opts.Signer != nil {
		methods = append(methods, gocrypto.PublicKeys(opts.Signer))
	}

	// 1. Explicit key file.
	keyPath := opts.KeyPath
	if keyPath == "" {
		if home, err := os.UserHomeDir(); err == nil {
			keyPath = filepath.Join(home, ".ssh", "id_rsa")
		}
	}
	if keyPath != "" && opts.Signer == nil {
		if data, err := os.ReadFile(keyPath); err == nil { //nolint:gosec // G304: keyPath is an SSH key path from user config
			if signer, err := gocrypto.ParsePrivateKey(data); err == nil {
				methods = append(methods, gocrypto.PublicKeys(signer))
			}
		}
	}

	// 2. SSH agent (SSH_AUTH_SOCK).
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock) //nolint:gosec // G704: SSH agent socket path is from SSH_AUTH_SOCK env, not user input
		if err == nil {
			agentConn = conn // caller closes this when Client.Close() is called
			ag := agent.NewClient(conn)
			methods = append(methods, gocrypto.PublicKeysCallback(ag.Signers))
		}
	}

	// 3. Password.
	password := opts.Password
	if password == "" {
		password = os.Getenv("EXALM_SSH_PASSWORD")
	}
	if password != "" {
		methods = append(methods, gocrypto.Password(password))
	}

	if len(methods) == 0 {
		return nil, nil, fmt.Errorf(
			"no auth method available — provide --key <path>, set SSH_AUTH_SOCK, or set EXALM_SSH_PASSWORD",
		)
	}
	return methods, agentConn, nil
}
