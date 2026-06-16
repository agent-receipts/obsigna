package main

import (
	"reflect"
	"sort"
	"testing"

	"github.com/agent-receipts/ar/daemon/internal/disclosecli"
	"github.com/agent-receipts/ar/daemon/internal/doctorcli"
	"github.com/agent-receipts/ar/daemon/internal/keyscli"
	"github.com/agent-receipts/ar/daemon/internal/listcli"
	"github.com/agent-receipts/ar/daemon/internal/showcli"
	"github.com/agent-receipts/ar/daemon/internal/verifycli"
	"github.com/agent-receipts/ar/daemon/internal/verifyeventcli"
)

// TestGoldenSurface pins the obsigna command surface to the frozen ADR-0030
// contract (the receipt + keys subtrees, the two carried-over diagnostics, and
// the closed flat-alias set). Any added, removed, or renamed noun/verb/alias
// changes this snapshot and fails CI — the frozen surface is a stability
// commitment of the same class as the /context/v1 spec URLs, so a drift must be
// a deliberate, reviewed migration, never an accident.
//
// If you are intentionally changing the surface: update ADR-0030 and the
// expectations below in the same change, and confirm the flat-alias invariant
// still holds (a flat alias may exist only for a verb that the legacy
// agent-receipts CLI already exposed).
func TestGoldenSurface(t *testing.T) {
	tr := commandTree()

	wantGroups := map[string][]string{
		"receipt": {"verify", "show", "list", "verify-event", "disclose"},
		"keys":    {"generate", "pubkey", "rotate"},
	}
	wantTopLeaves := []string{"doctor"}
	wantAliases := map[string]aliasTarget{
		"verify": {"receipt", "verify"},
		"show":   {"receipt", "show"},
	}

	// Groups: exact membership, and each group's verb set.
	if got := keys(tr.groups); !equalSet(got, mapKeys(wantGroups)) {
		t.Errorf("group set = %v, want %v", got, mapKeys(wantGroups))
	}
	if !equalSet(tr.groupOrder, mapKeys(wantGroups)) {
		t.Errorf("groupOrder = %v, want a permutation of %v", tr.groupOrder, mapKeys(wantGroups))
	}
	for name, wantVerbs := range wantGroups {
		g, ok := tr.groups[name]
		if !ok {
			t.Errorf("missing group %q", name)
			continue
		}
		if got := keys(g.leaves); !equalSet(got, wantVerbs) {
			t.Errorf("group %q verbs = %v, want %v", name, got, wantVerbs)
		}
		// order must list exactly the leaves, so help never omits or invents a verb.
		if !equalSet(g.order, keys(g.leaves)) {
			t.Errorf("group %q order = %v, want a permutation of its leaves %v", name, g.order, keys(g.leaves))
		}
		for _, v := range g.order {
			if g.leaves[v].run == nil {
				t.Errorf("group %q verb %q has nil run func", name, v)
			}
		}
	}

	// Top-level leaves (carried-over diagnostics).
	if got := keys(tr.topLeaves); !equalSet(got, wantTopLeaves) {
		t.Errorf("topLeaves = %v, want %v", got, wantTopLeaves)
	}
	if !equalSet(tr.topOrder, wantTopLeaves) {
		t.Errorf("topOrder = %v, want %v", tr.topOrder, wantTopLeaves)
	}

	// Aliases: exact membership and targets.
	if got := keys(tr.aliases); !equalSet(got, mapKeys(wantAliases)) {
		t.Errorf("alias set = %v, want %v", got, mapKeys(wantAliases))
	}
	if !equalSet(tr.aliasOrder, mapKeys(wantAliases)) {
		t.Errorf("aliasOrder = %v, want a permutation of %v", tr.aliasOrder, mapKeys(wantAliases))
	}
	for name, want := range wantAliases {
		got, ok := tr.aliases[name]
		if !ok {
			t.Errorf("missing alias %q", name)
			continue
		}
		if got != want {
			t.Errorf("alias %q -> %+v, want %+v", name, got, want)
		}
	}
}

// TestLeafWiring asserts each leaf is wired to the CORRECT implementation, not
// merely to some non-nil function. Without this, a registry mix-up that points
// two verbs at the same Run (e.g. both `verify` and `show` → showcli.Run) would
// pass TestGoldenSurface and TestAliasMatchesGrouped while silently running the
// wrong command — so the "frozen surface" guarantee would cover verb names but
// not behaviour.
func TestLeafWiring(t *testing.T) {
	tr := commandTree()

	wantGroupRun := map[string]map[string]runFunc{
		"receipt": {
			"verify":       verifycli.Run,
			"show":         showcli.Run,
			"list":         listcli.Run,
			"verify-event": verifyeventcli.Run,
			"disclose":     disclosecli.Run,
		},
		"keys": {
			"generate": keyscli.RunGenerate,
			"pubkey":   keyscli.RunPubkey,
			"rotate":   keyscli.RunRotate,
		},
	}
	for gname, verbs := range wantGroupRun {
		for v, want := range verbs {
			if got := tr.groups[gname].leaves[v].run; !sameFunc(got, want) {
				t.Errorf("group %q verb %q is wired to the wrong function", gname, v)
			}
		}
	}
	if !sameFunc(tr.topLeaves["doctor"].run, doctorcli.Run) {
		t.Error("doctor is wired to the wrong function")
	}
}

// sameFunc reports whether two func values point at the same code. Go funcs are
// not comparable with ==, so compare their code pointers via reflect.
func sameFunc(a, b runFunc) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// TestFlatAliasInvariant enforces ADR-0030's bound against alias sprawl: the flat
// aliases are the closed set {verify, show}, and each must resolve to a real verb
// in its group.
func TestFlatAliasInvariant(t *testing.T) {
	tr := commandTree()
	allowed := map[string]bool{"verify": true, "show": true}

	for name, target := range tr.aliases {
		if !allowed[name] {
			t.Errorf("flat alias %q is not in the closed set {verify, show}", name)
		}
		g, ok := tr.groups[target.group]
		if !ok {
			t.Errorf("alias %q targets unknown group %q", name, target.group)
			continue
		}
		if _, ok := g.leaves[target.verb]; !ok {
			t.Errorf("alias %q targets unknown verb %q in group %q", name, target.verb, target.group)
		}
	}
}

// TestLauncherSurface pins the process-launcher table (ADR-0031, ADR-0033,
// ADR-0035). `daemon` execs obsigna-daemon, `mcp` execs obsigna-mcp, and
// `collector` execs obsigna-collector. A launcher must never collide with a
// group, top leaf, or alias, or dispatch would be ambiguous.
func TestLauncherSurface(t *testing.T) {
	tr := commandTree()

	want := map[string]string{
		"daemon":    "obsigna-daemon",
		"mcp":       "obsigna-mcp",
		"collector": "obsigna-collector",
	}
	if got := keys(tr.launchers); !equalSet(got, mapKeys(want)) {
		t.Errorf("launcher set = %v, want %v", got, mapKeys(want))
	}
	if !equalSet(tr.launcherOrder, mapKeys(want)) {
		t.Errorf("launcherOrder = %v, want a permutation of %v", tr.launcherOrder, mapKeys(want))
	}
	for name, binary := range want {
		l, ok := tr.launchers[name]
		if !ok {
			t.Errorf("missing launcher %q", name)
			continue
		}
		if l.binary != binary {
			t.Errorf("launcher %q binary = %q, want %q", name, l.binary, binary)
		}
		if l.summary == "" {
			t.Errorf("launcher %q has an empty summary", name)
		}
	}

	// A launcher noun must not also be a group, top leaf, or alias.
	for name := range tr.launchers {
		if _, ok := tr.groups[name]; ok {
			t.Errorf("launcher %q collides with a group", name)
		}
		if _, ok := tr.topLeaves[name]; ok {
			t.Errorf("launcher %q collides with a top-level leaf", name)
		}
		if _, ok := tr.aliases[name]; ok {
			t.Errorf("launcher %q collides with an alias", name)
		}
	}
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func mapKeys[V any](m map[string]V) []string { return keys(m) }

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
