"""Integration tests: spawn a real Python process and exercise the full JS agent."""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

try:
    import frida

    _FRIDA_AVAILABLE = True
except ImportError:
    _FRIDA_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _FRIDA_AVAILABLE,
    reason="frida not installed",
)

from zap_repl.repl import Repl  # noqa: E402 — after frida guard


@pytest.fixture()
def python_session():
    """Spawn sys.executable via subprocess and yield a Frida session."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.PIPE,
    )
    session = None
    try:
        session = frida.attach(proc.pid)
    except Exception as exc:
        proc.kill()
        proc.wait()
        pytest.skip(f"frida.attach failed: {exc}")

    yield session

    try:
        session.detach()
    except Exception:
        pass
    proc.stdin.close()
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _allow_ptrace() -> None:
    """preexec_fn: let any process ptrace this child (Linux Yama ptrace_scope workaround).

    With ptrace_scope=1, frida.attach() can only trace children it spawned itself.
    PR_SET_PTRACER with PR_SET_PTRACER_ANY (-1) opts this specific process out of
    that restriction without requiring root or a global sysctl change.
    """
    import ctypes

    PR_SET_PTRACER = 0x59616D61  # "Yama" as a little-endian int
    PR_SET_PTRACER_ANY = -1
    try:
        ctypes.CDLL("libc.so.6").prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
    except Exception:
        pass


@pytest.fixture()
def attached_session():
    """Start sys.executable independently, then attach (no spawn); clean up after."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        preexec_fn=_allow_ptrace if sys.platform == "linux" else None,
    )
    # Give the process a moment to reach time.sleep so Python is fully initialised.
    time.sleep(0.3)

    session = None
    try:
        session = frida.attach(proc.pid)
    except Exception as exc:
        proc.terminate()
        proc.wait()
        pytest.skip(f"frida.attach failed: {exc}")

    yield session

    try:
        session.detach()
    except Exception:
        pass
    proc.terminate()
    proc.wait()


class TestAgentIntegration:
    def test_banner_returns_python_version(self, python_session):
        """banner() must return a string containing 'Python'."""
        repl = Repl(python_session)
        agent = repl._ensure_agent()
        probe = agent.exports_sync.banner()
        assert "error" not in probe, f"Agent init error: {probe.get('error')}"
        assert "Python" in probe.get("banner", "")

    def test_eval_expression(self, python_session):
        """1 + 1 must produce '2'."""
        repl = Repl(python_session)
        agent = repl._ensure_agent()
        result = agent.exports_sync.eval_python("1 + 1")
        assert result.get("output", "").strip() == "2"

    def test_eval_print(self, python_session):
        """print() output is captured."""
        repl = Repl(python_session)
        agent = repl._ensure_agent()
        result = agent.exports_sync.eval_python("print('hello zap_repl')")
        assert "hello zap_repl" in result.get("output", "")

    def test_state_persists_across_calls(self, python_session):
        """Assignment on call 1 must be visible on call 2."""
        repl = Repl(python_session)
        agent = repl._ensure_agent()
        agent.exports_sync.eval_python("_zap_repl_test_x = 42")
        result = agent.exports_sync.eval_python("print(_zap_repl_test_x)")
        assert result.get("output", "").strip() == "42"

    def test_import_persists_across_calls(self, python_session):
        """import on call 1 must be usable on call 2 (the original bug)."""
        repl = Repl(python_session)
        agent = repl._ensure_agent()
        agent.exports_sync.eval_python("_zap_repl_test_sep = 99")
        result = agent.exports_sync.eval_python("print(_zap_repl_test_sep)")
        assert result.get("output", "").strip() == "99"
        assert "NameError" not in result.get("output", "")

    def test_state_persists_with_delay(self, python_session):
        """State must survive a pause between calls (simulates user typing)."""
        import time

        repl = Repl(python_session)
        agent = repl._ensure_agent()
        agent.exports_sync.eval_python("_zap_repl_delay_x = 1")
        time.sleep(1.0)
        result = agent.exports_sync.eval_python("print(_zap_repl_delay_x)")
        assert result.get("output", "").strip() == "1"

    def test_exception_captured_not_on_stderr(self, python_session, capsys):
        """Exceptions go into the output buffer, not target/host stderr."""
        repl = Repl(python_session)
        agent = repl._ensure_agent()
        result = agent.exports_sync.eval_python("1 / 0")
        assert "ZeroDivisionError" in result.get("output", "")
        assert capsys.readouterr().err == ""


class TestRunCmd:
    """Tests for Repl.run_cmd() (the -c flag path)."""

    def test_run_cmd_spawn(self, python_session, capsys):
        """run_cmd prints output and exits (no banner, no REPL)."""
        repl = Repl(python_session)
        repl.run_cmd("print(1 + 1)")
        assert capsys.readouterr().out.strip() == "2"

    def test_run_cmd_attach(self, attached_session, capsys):
        """run_cmd works for an attached (not spawned) process."""
        repl = Repl(attached_session)
        repl.run_cmd("print(1 + 1)")
        assert capsys.readouterr().out.strip() == "2"

    def test_run_cmd_no_banner(self, python_session, capsys):
        """run_cmd must not print the Python version banner."""
        repl = Repl(python_session)
        repl.run_cmd("x = 1")
        out = capsys.readouterr().out
        assert "Python" not in out


class TestAgentAttach:
    """Same key tests using frida.attach() on an independently-started process."""

    def test_banner_attach(self, attached_session):
        repl = Repl(attached_session)
        agent = repl._ensure_agent()
        probe = agent.exports_sync.banner()
        assert "error" not in probe, f"Agent init error: {probe.get('error')}"
        assert "Python" in probe.get("banner", "")

    def test_state_persists_attach(self, attached_session):
        """x = 1 / print(x) must work when attached (not spawned)."""
        repl = Repl(attached_session)
        agent = repl._ensure_agent()
        agent.exports_sync.eval_python("_zap_repl_attach_x = 7")
        result = agent.exports_sync.eval_python("print(_zap_repl_attach_x)")
        assert result.get("output", "").strip() == "7"

    def test_state_persists_with_delay_attach(self, attached_session):
        """State must survive a pause in the attach case too."""
        repl = Repl(attached_session)
        agent = repl._ensure_agent()
        agent.exports_sync.eval_python("_zap_repl_attach_y = 2")
        time.sleep(1.0)
        result = agent.exports_sync.eval_python("print(_zap_repl_attach_y)")
        assert result.get("output", "").strip() == "2"
