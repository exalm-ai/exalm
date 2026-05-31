// Package registry holds the set of plugins available at runtime. Plugins
// register themselves in cmd/exalm/main.go via Register().
package registry

import (
	"fmt"
	"sort"
	"sync"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

var (
	mu      sync.RWMutex
	plugins = map[string]plugin.Plugin{}
)

// Register adds a plugin to the registry. Panics on duplicate names so
// conflicts are caught at startup, not at first use.
func Register(p plugin.Plugin) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := plugins[p.Name()]; exists {
		panic(fmt.Sprintf("plugin %q registered twice", p.Name()))
	}
	plugins[p.Name()] = p
}

// Get returns the plugin with the given name, or false if not found.
func Get(name string) (plugin.Plugin, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := plugins[name]
	return p, ok
}

// All returns all registered plugins, sorted by name.
func All() []plugin.Plugin {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]plugin.Plugin, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
