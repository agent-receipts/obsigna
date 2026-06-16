//go:build !linux && !darwin

package socket

import (
	"fmt"
	"net"
	"runtime"
)

// capturePeer is a build-only stub for platforms outside Phase 1 scope
// (Phase 1 ships Linux and macOS; Windows named pipes are tracked as a
// separate issue per #236). The daemon refuses to start on these platforms
// at startup via daemon.Run; this stub exists only so the package compiles
// in cross-platform CI.
func capturePeer(_ *net.UnixConn) (PeerCred, error) {
	return PeerCred{}, fmt.Errorf("obsigna-daemon: peer credential capture not implemented on %s", runtime.GOOS)
}
