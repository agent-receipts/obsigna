// Package configs exposes taxonomy mappings bundled into the mcp-proxy binary.
//
// Each *_taxonomy.json file in this directory is embedded at build time and
// merged into the runtime mapping list. User-provided -taxonomy entries should
// be applied first by callers so they win on tool_name conflict — the SDK's
// ClassifyToolCall iterates in order and returns on first match.
package configs

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"obsigna.dev/sdk/go/taxonomy"
)

//go:embed *_taxonomy.json
var taxonomyFiles embed.FS

// BundledTaxonomies returns the deduplicated set of mappings embedded in the
// binary. Files are processed in sorted source filename order, and mappings
// within each file are returned in their JSON order. The first mapping wins
// on duplicate tool_name across files.
func BundledTaxonomies() ([]taxonomy.TaxonomyMapping, error) {
	entries, err := taxonomyFiles.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded taxonomies: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_taxonomy.json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	seen := make(map[string]bool)
	var out []taxonomy.TaxonomyMapping
	for _, name := range names {
		raw, err := taxonomyFiles.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		var cfg taxonomy.TaxonomyConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		for _, m := range cfg.Mappings {
			if m.ToolName == "" || m.ActionType == "" {
				return nil, fmt.Errorf("%s: invalid mapping: tool_name and action_type must be non-empty", name)
			}
			if seen[m.ToolName] {
				continue
			}
			seen[m.ToolName] = true
			out = append(out, m)
		}
	}
	return out, nil
}

// BundledNames returns the basenames (without _taxonomy.json suffix) of the
// embedded files, sorted. Used for startup banners and diagnostics.
func BundledNames() []string {
	entries, err := taxonomyFiles.ReadDir(".")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, "_taxonomy.json") {
			continue
		}
		out = append(out, strings.TrimSuffix(name, "_taxonomy.json"))
	}
	sort.Strings(out)
	return out
}
