// Plugin SDK — standalone Go module for building Exalm plugins.
//
// Community plugin authors import this module directly:
//
//	go get github.com/exalm-ai/exalm/pkg/plugin
//
// The SDK has zero external dependencies — only the Go standard library.
// This makes it safe to embed in any project without dependency conflicts.
module github.com/exalm-ai/exalm/pkg/plugin

go 1.26.0

// Pinned to the patch that carries the current stdlib security fixes:
// go1.26.5 is affected by GO-2026-6089/6090/6091/5972/5026 (net/http,
// crypto/tls, html/template, encoding/asn1), all fixed in go1.26.6.
toolchain go1.26.6