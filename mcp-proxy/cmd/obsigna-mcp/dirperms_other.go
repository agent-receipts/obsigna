//go:build !unix

package main

import "io"

// warnDataDirPerms is a no-op on non-unix platforms. os.MkdirAll does not honour
// Unix permission bits on Windows, so a group/other-access warning would be
// meaningless there. The unix implementation lives in dirperms_unix.go.
func warnDataDirPerms(io.Writer) {}
