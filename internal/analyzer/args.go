package analyzer

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// SourcesFromArgs returns the list of source paths/globs to scan, drawn from
// args.FlagsMulti["file"] (preferred, repeatable) falling back to args.Flags["file"].
// If neither is set, returns nil (caller should rely on Stdin).
func SourcesFromArgs(args plugin.RunArgs) []string {
	if vs, ok := args.FlagsMulti["file"]; ok && len(vs) > 0 {
		out := make([]string, 0, len(vs))
		for _, v := range vs {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if v := strings.TrimSpace(args.Flags["file"]); v != "" {
		return []string{v}
	}
	return nil
}

// ParseConcurrency reads --concurrency from args, defaulting to fallback.
func ParseConcurrency(args plugin.RunArgs, fallback int) int {
	if v, ok := args.Flags["concurrency"]; ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// ParseChunkSize parses a human-friendly --chunk-size string (e.g. "200KB",
// "1MB", "64K", "4096"). Returns fallback on parse failure or zero/negative.
func ParseChunkSize(args plugin.RunArgs, fallback int) int {
	v, ok := args.Flags["chunk-size"]
	if !ok || v == "" {
		return fallback
	}
	n, err := parseSizeBytes(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func parseSizeBytes(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, strconv.ErrSyntax
	}
	i := 0
	for i < len(s) && (unicode.IsDigit(rune(s[i])) || s[i] == '.') {
		i++
	}
	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, err
	}
	unit := strings.ToUpper(strings.TrimSpace(s[i:]))
	var mult int
	switch unit {
	case "", "B":
		mult = 1
	case "K", "KB":
		mult = 1024
	case "M", "MB":
		mult = 1024 * 1024
	case "G", "GB":
		mult = 1024 * 1024 * 1024
	default:
		return 0, strconv.ErrSyntax
	}
	return int(num * float64(mult)), nil
}
