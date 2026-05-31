// Package sshtest provides an in-process SSH server for use in tests.
// It mirrors the pattern of net/http/httptest: callers start a server,
// get back an address and keys, run their test, then call Close().
//
// No real network infrastructure or on-disk key files are needed.
// The embedded server handles only "exec" channel requests, replying
// with a preset string per command.
//
// Usage:
//
//	srv := sshtest.NewServer(t, map[string]string{
//	    "uptime": " load average: 0.01\n",
//	})
//	defer srv.Close()
//
//	// Write private key to a temp file for plugins that read via --ssh-key.
//	keyFile := srv.WriteClientKeyFile(t)
//	args.Flags["host"]     = srv.Host()
//	args.Flags["ssh-port"] = srv.Port()
//	args.Flags["ssh-key"]  = keyFile
package sshtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	gocrypto "golang.org/x/crypto/ssh"
)

// Server is an in-process SSH server.
type Server struct {
	// Addr is the server's TCP address ("127.0.0.1:<port>").
	Addr string

	clientPriv *rsa.PrivateKey
	ln         net.Listener
}

// NewServer starts an embedded SSH server. replies maps command strings to
// the stdout response the server will send. An unknown command receives a
// "default reply for: <cmd>" response.
//
// Close must be called when the test is finished.
func NewServer(t testing.TB, replies map[string]string) *Server {
	t.Helper()

	hostKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("sshtest: generate host key: %v", err)
	}
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("sshtest: generate client key: %v", err)
	}

	hostSigner, err := gocrypto.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("sshtest: host signer: %v", err)
	}
	clientSigner, err := gocrypto.NewSignerFromKey(clientKey)
	if err != nil {
		t.Fatalf("sshtest: client signer: %v", err)
	}

	clientPub := clientSigner.PublicKey()
	cfg := &gocrypto.ServerConfig{
		PublicKeyCallback: func(_ gocrypto.ConnMetadata, key gocrypto.PublicKey) (*gocrypto.Permissions, error) {
			if string(key.Marshal()) == string(clientPub.Marshal()) {
				return &gocrypto.Permissions{}, nil
			}
			return nil, fmt.Errorf("unknown key")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sshtest: listen: %v", err)
	}

	srv := &Server{
		Addr:       ln.Addr().String(),
		clientPriv: clientKey,
		ln:         ln,
	}

	// Snapshot replies so callers can't mutate after start.
	fixed := make(map[string]string, len(replies))
	for k, v := range replies {
		fixed[k] = v
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go serveConn(conn, cfg, fixed)
		}
	}()

	return srv
}

// Close shuts down the server. Listener close errors are intentionally
// ignored — the server is already torn down in test teardown at this point.
func (s *Server) Close() { s.ln.Close() } //nolint:errcheck

// Host returns the server's hostname (always "127.0.0.1").
func (s *Server) Host() string {
	h, _, _ := net.SplitHostPort(s.Addr)
	return h
}

// Port returns the server's port as a string.
func (s *Server) Port() string {
	_, p, _ := net.SplitHostPort(s.Addr)
	return p
}

// WriteClientKeyFile writes the client private key to a temporary PEM file
// and returns its path. The file is removed when the test finishes.
func (s *Server) WriteClientKeyFile(t testing.TB) string {
	t.Helper()

	block, err := gocrypto.MarshalPrivateKey(s.clientPriv, "")
	if err != nil {
		t.Fatalf("sshtest: marshal private key: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "id_rsa")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("sshtest: write key file: %v", err)
	}
	return path
}

// ─── internal SSH server logic ────────────────────────────────────────────────

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
		ch, chanReqs, err := newChan.Accept()
		if err != nil {
			continue
		}
		go handleSession(ch, chanReqs, replies)
	}
}

func handleSession(ch gocrypto.Channel, reqs <-chan *gocrypto.Request, replies map[string]string) {
	defer ch.Close() //nolint:errcheck

	for req := range reqs {
		if req.Type != "exec" {
			req.Reply(false, nil) //nolint:errcheck
			continue
		}
		if len(req.Payload) < 4 {
			req.Reply(false, nil) //nolint:errcheck
			return
		}
		l := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 |
			int(req.Payload[2])<<8 | int(req.Payload[3])
		if 4+l > len(req.Payload) {
			req.Reply(false, nil) //nolint:errcheck
			return
		}
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
}
