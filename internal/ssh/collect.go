package ssh

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// RemoteSource holds the result of a successful remote log collection.
type RemoteSource struct {
	// Reader contains the collected log content.
	Reader io.Reader
	// Host is the remote host the content was collected from.
	Host string
}

// CollectIfNeeded checks args for the --host flag. When it is set it dials
// SSH, runs cmd on the remote host, and returns a RemoteSource. When --host
// is absent it returns (nil, nil) so the caller falls through to local
// file/stdin collection.
//
// Flag keys consumed from args.Flags:
//
//	host          — remote hostname or IP (required to activate SSH)
//	ssh-user      — SSH username (default: current OS user)
//	ssh-key       — path to PEM private key
//	ssh-port      — SSH port (default: 22)
//	ssh-password  — password fallback (prefer EXALM_SSH_PASSWORD env var)
func CollectIfNeeded(ctx context.Context, args plugin.RunArgs, cmd string) (*RemoteSource, error) {
	host := args.Flags["host"]
	if host == "" {
		return nil, nil
	}

	opts := Options{Host: host}

	if u := args.Flags["ssh-user"]; u != "" {
		opts.User = u
	}
	if k := args.Flags["ssh-key"]; k != "" {
		opts.KeyPath = k
	}
	if pw := args.Flags["ssh-password"]; pw != "" {
		opts.Password = pw
	}
	if p := args.Flags["ssh-port"]; p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			opts.Port = n
		}
	}

	fmt.Fprintf(args.Stderr, "ssh: connecting to %s...\n", host) //nolint:errcheck

	client, err := Dial(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	defer client.Close() //nolint:errcheck

	fmt.Fprintf(args.Stderr, "ssh: running remote command on %s\n", host) //nolint:errcheck

	r, err := client.RunCommand(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("ssh: remote command: %w", err)
	}

	return &RemoteSource{Reader: r, Host: host}, nil
}

// LogLinesFromArgs returns the --log-lines flag value (default: 5000).
func LogLinesFromArgs(args plugin.RunArgs, defaultVal int) int {
	if v := args.Flags["log-lines"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultVal
}
