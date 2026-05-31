package analyzer

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// progress writes one line per completed chunk to a sink, guarded by a mutex
// so writes from concurrent workers don't interleave.
type progress struct {
	w     io.Writer
	mu    sync.Mutex
	done  int64
	total int
}

func newProgress(w io.Writer, total int) *progress {
	return &progress{w: w, total: total}
}

// tick records that one chunk from source has finished and writes a status line.
// Source name is included — chunk *content* is never written here.
func (p *progress) tick(source string) {
	d := atomic.AddInt64(&p.done, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "[%d/%d] %s\n", d, p.total, source) //nolint:errcheck // best-effort progress output; write errors are not actionable
}
