package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAbsoluteResource covers the resolution rules: absolute paths pass through
// (cleaned), relative paths resolve against the supplied base, and an empty
// resource stays empty.
func TestAbsoluteResource(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		base     string
		want     string
	}{
		{"empty resource stays empty", "", "/work", ""},
		{"absolute passes through", "/etc/hosts", "/work", "/etc/hosts"},
		{"absolute is lexically cleaned", "/a/b/../c", "/work", "/a/c"},
		{"relative resolves against base", "out.go", "/work/project", "/work/project/out.go"},
		{"nested relative resolves against base", "pkg/x.go", "/work", "/work/pkg/x.go"},
		{"dot-relative resolves and cleans", "./out.txt", "/work", "/work/out.txt"},
		{"parent-relative resolves and cleans", "../sibling.go", "/work/project", "/work/sibling.go"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := absoluteResource(tc.resource, tc.base); got != tc.want {
				t.Errorf("absoluteResource(%q, %q) = %q; want %q", tc.resource, tc.base, got, tc.want)
			}
		})
	}
}

// TestAbsoluteResource_FallsBackToGetwd verifies that when the frame carries no
// (absolute) base, a relative resource is resolved against the hook process's
// own working directory — the directory Claude Code launched the hook in. The
// result must always be absolute.
func TestAbsoluteResource_FallsBackToGetwd(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	got := absoluteResource("out.go", "")
	if !filepath.IsAbs(got) {
		t.Fatalf("absoluteResource(out.go, \"\") = %q; want an absolute path", got)
	}
	if want := filepath.Join(wd, "out.go"); got != want {
		t.Errorf("absoluteResource(out.go, \"\") = %q; want %q", got, want)
	}
}

// TestAbsoluteResource_RelativeBaseFallsBack ensures a non-absolute base (which
// cannot anchor a resolution) is ignored in favour of the process working
// directory rather than producing a still-relative result.
func TestAbsoluteResource_RelativeBaseFallsBack(t *testing.T) {
	got := absoluteResource("out.go", "relative/base")
	if !filepath.IsAbs(got) {
		t.Errorf("absoluteResource(out.go, relative/base) = %q; want an absolute path", got)
	}
}
