package anchor

import (
	"fmt"
	"strings"
)

// OpenSink constructs a Sink from a backend spec of the form
// "<scheme>:<target>". The scheme selects the fate-sharing domain; the target
// is scheme-specific:
//
//	file:<path>    append-only newline-JSON log file (FileLog)
//	git:<dir>      git repository the agent UID cannot write (GitLog)
//	syslog:<tag>   local/forwarded syslog, tag optional (SyslogLog, unix only)
//
// A bare path with no recognised scheme is treated as file:<path> for
// convenience, mirroring how --anchor-log already takes a plain path.
func OpenSink(spec string) (Sink, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("anchor: empty sink spec")
	}
	scheme, target, hasScheme := strings.Cut(spec, ":")
	if !hasScheme {
		// No scheme: treat the whole spec as a file path.
		return OpenFileLog(spec)
	}
	switch scheme {
	case "file":
		return OpenFileLog(target)
	case "git":
		return OpenGitLog(target)
	case "syslog":
		return OpenSyslog(target)
	default:
		return nil, fmt.Errorf("anchor: unknown sink scheme %q (want file:, git:, or syslog:)", scheme)
	}
}

// OpenSinks constructs the fan-out list from a slice of specs, closing any
// already-opened sinks if a later spec fails so a partial failure does not
// leak file handles or half-initialised repos.
func OpenSinks(specs []string) ([]Sink, error) {
	sinks := make([]Sink, 0, len(specs))
	for _, spec := range specs {
		s, err := OpenSink(spec)
		if err != nil {
			for _, opened := range sinks {
				_ = opened.Close()
			}
			return nil, err
		}
		sinks = append(sinks, s)
	}
	return sinks, nil
}
