import argparse
import os
import shutil
import signal
import subprocess
import sys

import frida

from ._zap_common import _explain_attach_failure, _explain_codesign_failure
from .repl import Repl


def _resolve_program(name: str) -> str:
    """Return an absolute path for *name*, searching PATH if needed."""
    if os.sep in name or (os.altsep and os.altsep in name):
        return name
    resolved = shutil.which(name)
    if resolved is None:
        print(f"zap-repl: command not found: {name}", file=sys.stderr)
        sys.exit(1)
    return resolved


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="zap-repl",
        description="Attach to a running Python process and open a REPL.",
    )
    parser.add_argument(
        "-p",
        dest="pid",
        type=int,
        metavar="PID",
        help="attach to an already-running process by PID",
    )
    parser.add_argument(
        "--prefix",
        action="store_true",
        default=False,
        help="prefix each output line with 'remote: '",
    )
    parser.add_argument(
        "-c",
        dest="cmd",
        metavar="STMT",
        default=None,
        help="run a single Python statement and exit (no banner, no REPL)",
    )
    # REMAINDER collects everything from the first positional onward without
    # interpreting flags, so `zap-repl python -c 'stmt'` works as expected.
    parser.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        metavar="PROGRAM [ARG ...]",
        help="spawn this program (with optional arguments) and attach to it",
    )
    args = parser.parse_args()

    if args.pid is not None and args.argv:
        parser.error("specify either -p PID or PROGRAM, not both")
    if args.pid is None and not args.argv:
        parser.error("one of -p PID or PROGRAM is required")

    proc: subprocess.Popen[bytes] | None = None

    if args.pid is not None:
        pid = args.pid
    else:
        if len(args.argv) == 1:
            # Give it something to do that we can still exit cleanly
            args.argv.append("-c")
            args.argv.append("import sys; sys.stdin.read()")
        argv = [_resolve_program(args.argv[0])] + args.argv[1:]
        try:
            # stdin=PIPE: we hold the write end open so the spawned process
            # blocks on stdin rather than seeing EOF immediately.  Closing
            # proc.stdin on exit sends EOF, giving the process a chance to
            # exit cleanly before we SIGTERM / SIGKILL it.
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE)
        except PermissionError:
            if sys.platform == "darwin":
                print(_explain_codesign_failure(argv[0]), file=sys.stderr)
            else:
                print(f"Permission denied spawning {argv[0]!r}.", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError:
            print(f"zap-repl: command not found: {argv[0]}", file=sys.stderr)
            sys.exit(1)
        pid = proc.pid

    try:
        session = frida.attach(pid)
    except frida.PermissionDeniedError as exc:
        if proc is not None:
            proc.kill()
            proc.wait()
        if sys.platform == "linux":
            print(_explain_attach_failure(pid), file=sys.stderr)
        elif sys.platform == "darwin":
            print(_explain_codesign_failure(args.argv[0]), file=sys.stderr)
        else:
            print(f"Permission denied attaching to PID {pid}: {exc}.", file=sys.stderr)
        sys.exit(1)
    except frida.ProcessNotFoundError:
        print(f"No process with PID {pid} found.", file=sys.stderr)
        if sys.platform == "linux":
            print(_explain_attach_failure(pid), file=sys.stderr)
        sys.exit(1)

    repl = Repl(session, prefix=args.prefix)
    try:
        if args.cmd is not None:
            repl.run_cmd(args.cmd)
        else:
            repl.run()
    finally:
        session.detach()
        if proc is not None:
            # Close stdin → spawned process gets EOF and can exit cleanly.
            try:
                if proc.stdin is not None:
                    proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=1.0)
                return
            except subprocess.TimeoutExpired:
                pass
            # Still alive after 1 s: escalate.
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    main()
