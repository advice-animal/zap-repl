# This could be a separate library but it's small enough to just vendor.
# These are the helpful error messages when we can't attach to a process.

import os


def _ptrace_scope() -> int | None:
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _explain_codesign_failure(program: str) -> str:
    lines = [
        f"Permission denied: cannot attach to {program!r}.",
        "",
        "On macOS, system-signed binaries (e.g. /usr/bin/python3) have the hardened",
        "runtime enabled, which blocks Frida from injecting code.",
        "",
        "Use a non-system Python instead:",
        "  uv python install 3.x  →  zapl $(uv python find 3.x)",
    ]
    return "\n".join(lines)


def _explain_attach_failure(pid: int) -> str:
    scope = _ptrace_scope()
    euid = os.geteuid()
    lines = [f"Could not attach to PID {pid}."]
    if scope is not None and scope != 0:
        lines.append(
            f"  /proc/sys/kernel/yama/ptrace_scope is {scope} (not 0),"
            " which restricts ptrace to privileged processes."
        )
    if euid != 0:
        lines.append(f"  Running as euid {euid} (not root).")
    if scope is not None and scope != 0 and euid != 0:
        lines.append(
            "Fix: run with sudo, or:"
            " echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope"
        )
    elif euid != 0:
        lines.append("Try running with sudo.")
    return "\n".join(lines)
