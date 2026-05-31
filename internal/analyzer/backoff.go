package analyzer

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// retryableMarkers is a conservative list. Providers report rate limits
// inconsistently; matching error strings is uglier than a typed error but
// avoids growing the plugin.LLMClient interface (DEVELOPMENT.md plugin contract).
var retryableMarkers = []string{
	"429",
	"rate limit",
	"rate_limit",
	"too many requests",
	"overloaded",
	"server is overloaded",
	"service unavailable",
	"503",
	"504",
	"timeout",
}

// isRetryable returns true if the error looks like a transient provider issue.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range retryableMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// sleepWithJitter blocks for base * 2^attempt with ±25% jitter, capped at 30s.
func sleepWithJitter(ctx context.Context, attempt int, base time.Duration) error {
	d := base << attempt
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(d / 4))) //nolint:gosec // G404: jitter does not require cryptographic randomness
	wait := d + jitter
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// callWithBackoff invokes the LLM, retrying on retryable errors up to retries times.
func callWithBackoff(ctx context.Context, llm plugin.LLMClient, req plugin.CompleteRequest, retries int) (plugin.CompleteResponse, error) {
	var last error
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return plugin.CompleteResponse{}, ctx.Err()
		}
		resp, err := llm.Complete(ctx, req)
		if err == nil {
			return resp, nil
		}
		last = err
		if !isRetryable(err) {
			return plugin.CompleteResponse{}, err
		}
		if attempt == retries {
			break
		}
		if waitErr := sleepWithJitter(ctx, attempt, 500*time.Millisecond); waitErr != nil {
			return plugin.CompleteResponse{}, waitErr
		}
	}
	return plugin.CompleteResponse{}, errors.New("llm: gave up after retries: " + last.Error())
}
