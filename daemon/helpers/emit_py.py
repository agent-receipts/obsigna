#!/usr/bin/env python3
"""Test helper: Emit a frame using the Python SDK.

Usage: python3 emit_py.py <socket_path> <session_id> <channel> <tool_name> <decision>
"""

import sys
import os

# Add the Python SDK to the path
repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sdk_py_path = os.path.join(repo_root, "sdk/py/src")
sys.path.insert(0, sdk_py_path)

from obsigna import DaemonEmitter

def main():
    if len(sys.argv) != 6:
        print("Usage: emit_py.py <socket> <session> <channel> <tool> <decision>", file=sys.stderr)
        sys.exit(1)

    socket_path, session_id, channel, tool_name, decision = sys.argv[1:]

    emitter = DaemonEmitter(socket_path=socket_path, session_id=session_id)
    emitter.emit(
        channel=channel,
        tool_name=tool_name,
        decision=decision,
    )
    # The Python SDK's emit() returns None even on success
    sys.exit(0)

if __name__ == "__main__":
    main()
