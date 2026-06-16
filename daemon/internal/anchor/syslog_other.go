//go:build !unix

package anchor

import "errors"

// OpenSyslog is unavailable off unix (log/syslog is unix-only). The daemon
// itself runs only on linux/darwin, so this branch exists purely to keep the
// package buildable on other platforms for tooling (go vet, cross-compile).
func OpenSyslog(string) (Sink, error) {
	return nil, errors.New("anchor: syslog sink is only supported on unix")
}
