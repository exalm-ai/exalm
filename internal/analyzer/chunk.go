package analyzer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Chunk is one slice of input data ready for an LLM call.
type Chunk struct {
	Source        string // file path or "<stdin>"
	Index         int    // 0-based position within its source
	TotalInSource int    // total chunks for this source
	Bytes         int
	Data          []byte
}

// collectChunks walks Spec.Sources (with glob expansion) and Spec.Stdin,
// returning a flat slice of chunks sized to ChunkBytes at line boundaries.
func collectChunks(s Spec) ([]Chunk, error) {
	var all []Chunk

	if len(s.Sources) == 0 {
		if s.Stdin == nil {
			return nil, errors.New("no sources and no stdin")
		}
		chunks, err := chunkReader(s.Stdin, "<stdin>", s.ChunkBytes, s.MaxInputBytes)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		return chunks, nil
	}

	paths, err := expandSources(s.Sources)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no files matched: %v", s.Sources)
	}

	for _, p := range paths {
		f, err := os.Open(p) //nolint:gosec // G304: path comes from configured Sources, not user-supplied HTTP input
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", p, err)
		}
		chunks, err := chunkReader(f, p, s.ChunkBytes, s.MaxInputBytes)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", p, err)
		}
		all = append(all, chunks...)
	}
	return all, nil
}

// expandSources resolves glob patterns and deduplicates. Returns paths sorted
// for determinism.
func expandSources(sources []string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, src := range sources {
		matches, err := filepath.Glob(src)
		if err != nil {
			return nil, fmt.Errorf("glob %q: %w", src, err)
		}
		if len(matches) == 0 {
			info, statErr := os.Stat(src)
			if statErr == nil && !info.IsDir() {
				matches = []string{src}
			}
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil || info.IsDir() {
				continue
			}
			seen[m] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// chunkReader streams r into chunks of approximately chunkBytes, never
// splitting a line. If maxBytes > 0, reads stop once total bytes reach that cap.
func chunkReader(r io.Reader, source string, chunkBytes int, maxBytes int64) ([]Chunk, error) {
	if chunkBytes <= 0 {
		chunkBytes = defaultChunkBytes
	}
	scanner := bufio.NewScanner(r)
	// Allow lines up to chunkBytes themselves; bufio's default 64K is too tight
	// for some JSON-per-line journalctl output.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, chunkBytes+64*1024)

	var chunks []Chunk
	var current []byte
	var totalRead int64

	flush := func() {
		if len(current) == 0 {
			return
		}
		out := make([]byte, len(current))
		copy(out, current)
		chunks = append(chunks, Chunk{
			Source: source,
			Index:  len(chunks),
			Bytes:  len(out),
			Data:   out,
		})
		current = current[:0]
	}

	for scanner.Scan() {
		line := scanner.Bytes()
		lineLen := len(line) + 1 // +1 for newline
		totalRead += int64(lineLen) //nolint:gosec // G115: lineLen is from len() which is always non-negative
		if maxBytes > 0 && totalRead > maxBytes {
			break
		}
		if len(current)+lineLen > chunkBytes && len(current) > 0 {
			flush()
		}
		current = append(current, line...)
		current = append(current, '\n')
	}
	flush()
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	for i := range chunks {
		chunks[i].TotalInSource = len(chunks)
	}
	return chunks, nil
}
