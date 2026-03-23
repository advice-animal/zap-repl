"""Get some coverage, any coverage, on `__main__.py`"""

import subprocess
import sys


def test_help():
    output = subprocess.check_output(
        [sys.executable, "-m", "zap_repl", "--help"], timeout=5
    )
    assert b"attach to an already-running process by PID" in output


def test_smoke_nocmd():
    output = subprocess.check_output(
        [
            sys.executable,
            "-m",
            "coverage",
            "run",
            "-m",
            "zap_repl",
            "-c",
            "print('X', 1+1, 2+2)",
            "python",
        ],
        timeout=5,
    )
    assert b"X 2 4" in output


def test_smoke():
    output = subprocess.check_output(
        [
            sys.executable,
            "-m",
            "zap_repl",
            "-c",
            "print('X', 1+1, 2+2)",
            "python",
            "-c",
            "import time; time.sleep(60)",
        ],
        timeout=5,
    )
    assert b"X 2 4" in output


def test_interactive():
    proc = subprocess.Popen(
        [sys.executable, "-m", "coverage", "run", "-m", "zap_repl", "python"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    output, _ = proc.communicate(b"unbound_local\nprint('X', 1+1, 2+2)\n", timeout=5)
    assert b"X 2 4" in output
