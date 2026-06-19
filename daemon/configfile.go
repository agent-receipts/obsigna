package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultParameterDisclosure is the disclosure policy written into the starter
// config by `obsigna-daemon --init`. "true" discloses every action, so a fresh
// install records recoverable parameters for the whole audit trail out of the
// box — the experience an operator evaluating Obsigna expects to see. Operators
// who want a narrower policy edit the generated config (e.g. "high" for
// high-risk actions only, or an action-type allowlist) and, for production,
// move the forensic private key off-host.
const DefaultParameterDisclosure = "true"

// FileConfig is the subset of Config that can be set from the TOML config
// file. Every field mirrors an existing flag/env var so operators have one
// mental model: the TOML key is the flag name with dashes turned into
// underscores. Pointer-typed fields distinguish "absent in the file" (nil,
// so a lower-precedence default/env/flag wins) from "explicitly set to the
// zero value" (e.g. unsafe_socket_path = false) — the config file is the
// lowest-priority layer, so an absent key must never clobber env or flags.
type FileConfig struct {
	Socket              *string           `toml:"socket"`
	DB                  *string           `toml:"db"`
	Key                 *string           `toml:"key"`
	PublicKey           *string           `toml:"public_key"`
	ForensicPublicKey   *string           `toml:"forensic_public_key"`
	ChainID             *string           `toml:"chain_id"`
	IssuerID            *string           `toml:"issuer_id"`
	VerificationMethod  *string           `toml:"verification_method"`
	ParameterDisclosure *DisclosureConfig `toml:"parameter_disclosure"`
	RedactPatterns      *string           `toml:"redact_patterns"`
	UnsafeSocketPath    *bool             `toml:"unsafe_socket_path"`
	// ShutdownDeadline accepts a Go duration string, e.g. "200ms" or "1s".
	ShutdownDeadline *Duration `toml:"shutdown_deadline"`
	// CheckpointAnchor mirrors --checkpoint-anchor: a comma-separated list of
	// out-of-band checkpoint sink specs (file:/git:/syslog:). CheckpointCadence
	// mirrors --checkpoint-cadence.
	CheckpointAnchor  *string `toml:"checkpoint_anchor"`
	CheckpointCadence *int    `toml:"checkpoint_cadence"`
	// MaxErrorLen and MaxPromptPreviewLen mirror --max-error-len and
	// --max-prompt-preview-len: rune caps on the inline outcome.error and
	// intent.prompt_preview fields (issue #478).
	MaxErrorLen         *int `toml:"max_error_len"`
	MaxPromptPreviewLen *int `toml:"max_prompt_preview_len"`
}

// DisclosureConfig is the parsed `parameter_disclosure` config-file value. It
// normalises three accepted TOML shapes into the policy string consumed by
// pipeline.ParseDisclosurePolicy:
//
//   - boolean: true → "true", false → "false". Preserves backwards
//     compatibility with configs (and the documented default) written when
//     parameter_disclosure was a bool, instead of failing to decode.
//   - string: a policy keyword ("false"/"true"/"high") or a comma-separated
//     action-type allowlist, used verbatim.
//   - array of strings: an action-type allowlist, joined with commas — the
//     natural TOML/JSON spelling of the list form.
//
// The flag and environment-variable layers only accept the string spelling
// (they have no array type); the array form is a TOML convenience.
type DisclosureConfig struct {
	Value string
}

// UnmarshalTOML implements toml.Unmarshaler so the parameter_disclosure key can
// be a boolean, a string, or an array of strings.
func (d *DisclosureConfig) UnmarshalTOML(v any) error {
	switch x := v.(type) {
	case bool:
		if x {
			d.Value = "true"
		} else {
			d.Value = "false"
		}
	case string:
		d.Value = x
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return fmt.Errorf("parameter_disclosure array entries must be strings, got %T", e)
			}
			parts = append(parts, s)
		}
		d.Value = strings.Join(parts, ",")
	default:
		return fmt.Errorf("parameter_disclosure must be a boolean, string, or array of strings, got %T", v)
	}
	return nil
}

// Duration wraps time.Duration so it decodes from a TOML string such as
// "200ms" or "1s" via Go's time.ParseDuration. BurntSushi/toml has no native
// duration type; without this an operator would have to write nanoseconds.
type Duration struct {
	time.Duration
}

// UnmarshalText implements encoding.TextUnmarshaler so toml.DecodeFile parses
// a quoted duration string into a time.Duration. An empty string is rejected
// — a key present in the file but blank is a misconfiguration, not a default.
func (d *Duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", string(text), err)
	}
	d.Duration = parsed
	return nil
}

// DefaultConfigPath returns the per-user TOML config path used when --config
// is not given: $XDG_DATA_HOME/agent-receipts/daemon.toml, co-located with
// receipts.db and the signing key (DefaultDBPath/DefaultKeyPath). Returns ""
// when the XDG data home cannot be resolved (no XDG_DATA_HOME and no home
// directory), matching the other Default*Path helpers.
func DefaultConfigPath() string {
	dh := xdgDataHome()
	if dh == "" {
		return ""
	}
	return filepath.Join(dh, "agent-receipts", "daemon.toml")
}

// starterConfigTemplate is the commented TOML written by `obsigna-daemon
// --init`. The two %q placeholders are the forensic public-key path and the
// disclosure policy; both round-trip back through LoadConfigFile.
const starterConfigTemplate = "# obsigna daemon configuration — generated by `obsigna-daemon --init`.\n" +
	"# Reference: https://obsigna.dev/reference/configuration/\n" +
	"\n" +
	"# Parameter disclosure (ADR-0012): encrypt each action's parameters into the\n" +
	"# signed receipt so an operator holding the forensic private key can recover\n" +
	"# the raw inputs later with `obsigna receipt disclose`. The daemon never holds\n" +
	"# the private key, so it cannot read what it wrote. \"true\" discloses every\n" +
	"# action; use \"high\" for high-risk actions only, a comma-separated action-type\n" +
	"# allowlist (e.g. \"fs.write,net.http\"), or false to record hashes alone.\n" +
	"forensic_public_key = %q\n" +
	"parameter_disclosure = %q\n"

// WriteStarterConfig writes a commented starter config that enables parameter
// disclosure to path, unless a file already exists there. It reports whether it
// wrote: (false, nil) means a config was already present and was left untouched
// — `obsigna-daemon --init` never clobbers an operator's hand-edited config.
//
// Like the key writers it opens with O_CREATE|O_EXCL|O_NOFOLLOW so it refuses to
// follow a symlink or overwrite an existing dirent, closing the same TOCTOU
// window. Unlike the key writers the file is not secret (mode 0644): it holds
// only paths and a policy string, never key material.
func WriteStarterConfig(path, forensicPublicKeyPath, disclosure string) (bool, error) {
	if path == "" {
		return false, errors.New("config path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return false, fmt.Errorf("create config dir: %w", err)
	}

	content := fmt.Sprintf(starterConfigTemplate, forensicPublicKeyPath, disclosure)
	// Reuse the key writers' fail-closed primitive (O_CREATE|O_EXCL|O_NOFOLLOW,
	// fchmod, rollback) rather than re-implementing it; the only difference here
	// is that a pre-existing config is a skip, not an error.
	switch err := writeNewSecretFile(path, []byte(content), 0o644); {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrExist):
		// O_EXCL fires for a symlink too (EEXIST can win over ELOOP). A real
		// file means "operator already has a config, leave it"; a symlink is a
		// planted dirent we must refuse, not silently report as a skip.
		if fi, lerr := os.Lstat(path); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("refusing to follow symlink at %s", path)
		}
		return false, nil
	default:
		return false, fmt.Errorf("write config %s: %w", path, err)
	}
}

// LoadConfigFile reads and strictly decodes the TOML config at path.
//
//   - required=false (default-path load): a missing file is not an error —
//     it returns (nil, nil) so the daemon runs on flags/env alone. Any other
//     read or parse error is returned, because a present-but-broken config is
//     a misconfiguration we refuse to silently ignore.
//   - required=true (explicit --config): a missing file IS an error — the
//     operator named a path that does not exist, which is almost certainly a
//     typo rather than an intentional "no config".
//
// Unknown keys are rejected: a typo'd key (e.g. "sockett") would otherwise be
// silently ignored, leaving the daemon running with a different config than
// the operator believes they set. This mirrors the redact-pattern loader's
// "reject malformed config rather than silently degrade" stance.
func LoadConfigFile(path string, required bool) (*FileConfig, error) {
	if path == "" {
		return nil, errors.New("config path is empty")
	}
	var fc FileConfig
	md, err := toml.DecodeFile(path, &fc)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !required {
			return nil, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("config file %s does not exist", path)
		}
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config %s: unknown key(s): %v", path, keys)
	}
	return &fc, nil
}
