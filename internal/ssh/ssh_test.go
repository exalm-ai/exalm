package ssh_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	gocrypto "golang.org/x/crypto/ssh"

	exassh "github.com/exalm-ai/exalm/internal/ssh"
)

// ─── embedded test SSH server ─────────────────────────────────────────────────

// testServer starts an in-process SSH server that accepts the given signer
// for host authentication and any public-key authentication.
// It handles only a single "exec" channel and echoes a fixed reply per command.
func testServer(t *testing.T, hostSigner gocrypto.Signer, clientPub gocrypto.PublicKey, replies map[string]string) (addr string, cleanup func()) {
	t.Helper()

	cfg := &gocrypto.ServerConfig{
		PublicKeyCallback: func(conn gocrypto.ConnMetadata, key gocrypto.PublicKey) (*gocrypto.Permissions, error) {
			if string(key.Marshal()) == string(clientPub.Marshal()) {
				return &gocrypto.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(conn, cfg, replies)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func serveConn(conn net.Conn, cfg *gocrypto.ServerConfig, replies map[string]string) {
	srvConn, chans, reqs, err := gocrypto.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer srvConn.Close() //nolint:errcheck

	go gocrypto.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(gocrypto.UnknownChannelType, "unsupported") //nolint:errcheck
			continue
		}
		ch, reqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func(ch gocrypto.Channel, reqs <-chan *gocrypto.Request) {
			defer ch.Close() //nolint:errcheck
			for req := range reqs {
				if req.Type == "exec" {
					// The payload is: uint32(len) + command bytes.
					if len(req.Payload) < 4 {
						req.Reply(false, nil) //nolint:errcheck
						continue
					}
					l := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
					cmd := string(req.Payload[4 : 4+l])
					req.Reply(true, nil) //nolint:errcheck

					reply, ok := replies[cmd]
					if !ok {
						reply = "default reply for: " + cmd
					}
					io.WriteString(ch, reply)            //nolint:errcheck
					ch.SendRequest("exit-status", false, //nolint:errcheck
						gocrypto.Marshal(struct{ Status uint32 }{0}))
					return
				}
				req.Reply(false, nil) //nolint:errcheck
			}
		}(ch, reqs)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func generateKeys(t *testing.T) (hostSigner, clientSigner gocrypto.Signer) {
	t.Helper()
	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	hs, err := gocrypto.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cs, err := gocrypto.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("client signer: %v", err)
	}
	return hs, cs
}

// ─── tests ────────────────────────────────────────────────────────────────────

func TestDial_RunCommand(t *testing.T) {
	hostSigner, clientSigner := generateKeys(t)
	replies := map[string]string{
		"echo hello": "hello\n",
		"uptime":     " 13:00:00 up 1 day, load average: 0.01\n",
	}
	addr, cleanup := testServer(t, hostSigner, clientSigner.PublicKey(), replies)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}

	ctx := context.Background()
	client, err := exassh.Dial(ctx, exassh.Options{
		Host:    host,
		Port:    port,
		User:    "testuser",
		Signer:  clientSigner,
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close() //nolint:errcheck

	t.Run("echo", func(t *testing.T) {
		r, err := client.RunCommand(ctx, "echo hello")
		if err != nil {
			t.Fatalf("RunCommand: %v", err)
		}
		got, _ := io.ReadAll(r)
		if strings.TrimSpace(string(got)) != "hello" {
			t.Errorf("got %q, want %q", string(got), "hello")
		}
	})

	t.Run("uptime", func(t *testing.T) {
		r, err := client.RunCommand(ctx, "uptime")
		if err != nil {
			t.Fatalf("RunCommand: %v", err)
		}
		got, _ := io.ReadAll(r)
		if !strings.Contains(string(got), "load average") {
			t.Errorf("uptime output missing 'load average': %q", string(got))
		}
	})
}

func TestDial_ContextCancel(t *testing.T) {
	hostSigner, clientSigner := generateKeys(t)
	replies := map[string]string{}
	addr, cleanup := testServer(t, hostSigner, clientSigner.PublicKey(), replies)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := exassh.Dial(ctx, exassh.Options{
		Host:    host,
		Port:    port,
		User:    "testuser",
		Signer:  clientSigner,
		Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error after context cancel, got nil")
	}
}

func TestDial_BadPort(t *testing.T) {
	_, clientSigner := generateKeys(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := exassh.Dial(ctx, exassh.Options{
		Host:    "127.0.0.1",
		Port:    1, // nothing listening
		User:    "testuser",
		Signer:  clientSigner,
		Timeout: 1 * time.Second,
	})
	if err == nil {
		t.Fatal("expected dial error to unreachable port, got nil")
	}
}

func TestDial_EmptyHost(t *testing.T) {
	_, err := exassh.Dial(context.Background(), exassh.Options{})
	if err == nil {
		t.Fatal("expected error for empty host, got nil")
	}
}

func TestCommandPresets(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"syslog journald", exassh.SyslogCmd(true, 100), "journalctl"},
		{"syslog fallback", exassh.SyslogCmd(false, 200), "tail"},
		{"httplog", exassh.HTTPLogCmd("", 500), "tail"},
		{"httplog custom path", exassh.HTTPLogCmd("/var/log/apache2/access.log", 0), "/var/log/apache2"},
		{"http error log", exassh.HTTPErrorLogCmd("", 0), "tail"},
		{"auth log", exassh.AuthLogCmd(0), "journalctl"},
		{"eventlog", exassh.EventLogCmd("Security", 0), "Get-WinEvent"},
		{"iis log", exassh.IISLogCmd("", 0), "Get-ChildItem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(tt.cmd, tt.want) {
				t.Errorf("command %q does not contain %q", tt.cmd, tt.want)
			}
		})
	}
}

// TestCommandInjectionPrevention verifies that unsafe values supplied via
// --log-name and --log-dir are rejected and replaced with safe defaults,
// preventing command injection into the remote PowerShell commands.
func TestCommandInjectionPrevention(t *testing.T) {
	t.Run("eventlog_rejects_unknown_channel", func(t *testing.T) {
		malicious := `'; Remove-Item -Recurse C:\; #`
		cmd := exassh.EventLogCmd(malicious, 100)
		if strings.Contains(cmd, malicious) {
			t.Errorf("malicious log name was not sanitised: %q", cmd)
		}
		if !strings.Contains(cmd, "Security") {
			t.Errorf("expected fallback to Security channel, got: %q", cmd)
		}
	})

	t.Run("iis_rejects_path_with_metachar", func(t *testing.T) {
		malicious := `C:\logs'; Remove-Item C:\`
		cmd := exassh.IISLogCmd(malicious, 100)
		if strings.Contains(cmd, malicious) {
			t.Errorf("malicious log dir was not sanitised: %q", cmd)
		}
		if !strings.Contains(cmd, `W3SVC1`) {
			t.Errorf("expected fallback to default IIS path, got: %q", cmd)
		}
	})

	t.Run("eventlog_accepts_valid_channels", func(t *testing.T) {
		for _, ch := range []string{"Security", "System", "Application", "Setup"} {
			cmd := exassh.EventLogCmd(ch, 100)
			if !strings.Contains(cmd, ch) {
				t.Errorf("valid channel %q was rejected: %q", ch, cmd)
			}
		}
	})
}
