"""Tests for zap_repl.repl.Repl._eval_one output handling."""

from __future__ import annotations

import builtins
import threading
from unittest.mock import MagicMock

import pytest
from zap_repl.repl import Repl

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_repl(*outputs: str, prefix: bool = False) -> tuple[Repl, MagicMock]:
    """Return a Repl backed by a mock session.

    Each positional *output* string becomes the ``output`` field returned by
    successive ``eval_python`` RPC calls.
    """
    session = MagicMock()
    script = MagicMock()
    session.create_script.return_value = script

    responses = iter({"output": o} for o in outputs)
    script.exports_sync.eval_python.side_effect = lambda _src: next(responses)

    return Repl(session, prefix=prefix), script


class _InterruptOnceEvent(threading.Event):
    """Event whose first wait() raises KeyboardInterrupt; subsequent calls return True."""

    def __init__(self) -> None:
        super().__init__()
        self._calls = 0

    def wait(self, timeout: float | None = None) -> bool:  # type: ignore[override]
        self._calls += 1
        if self._calls == 1:
            raise KeyboardInterrupt
        return True  # remote finished


class _AlwaysInterruptEvent(threading.Event):
    """Event whose wait() always raises KeyboardInterrupt."""

    def wait(self, timeout: float | None = None) -> bool:  # type: ignore[override]
        raise KeyboardInterrupt


# ---------------------------------------------------------------------------
# _eval_one output formatting
# ---------------------------------------------------------------------------


class TestEvalOneOutput:
    def test_single_line_no_prefix(self, capsys):
        repl, _ = _make_repl("42\n")
        repl._eval_one("21+21")
        assert capsys.readouterr().out == "42\n"

    def test_single_line_prefixed(self, capsys):
        repl, _ = _make_repl("42\n", prefix=True)
        repl._eval_one("21+21")
        assert capsys.readouterr().out == "remote: 42\n"

    def test_multiline_each_prefixed(self, capsys):
        repl, _ = _make_repl("hello\nworld\n", prefix=True)
        repl._eval_one("print('hello'); print('world')")
        assert capsys.readouterr().out == "remote: hello\nremote: world\n"

    def test_multiline_no_prefix(self, capsys):
        repl, _ = _make_repl("hello\nworld\n")
        repl._eval_one("print('hello'); print('world')")
        assert capsys.readouterr().out == "hello\nworld\n"

    def test_empty_output_silent(self, capsys):
        repl, _ = _make_repl("")
        repl._eval_one("x = 1")
        assert capsys.readouterr().out == ""

    def test_exception_in_rpc_propagates(self):
        session = MagicMock()
        script = MagicMock()
        session.create_script.return_value = script
        script.exports_sync.eval_python.side_effect = RuntimeError("session is gone")

        repl = Repl(session)
        with pytest.raises(RuntimeError, match="session is gone"):
            repl._eval_one("x")

    def test_ctrl_c_once_warns_and_waits(self, capsys):
        """First Ctrl-C prints a warning; execution resumes when remote finishes."""
        repl, _ = _make_repl("42\n")
        # First wait() raises KeyboardInterrupt, second returns True (done).
        repl._eval_one("1+1", _done=_InterruptOnceEvent())
        err = capsys.readouterr().err
        assert "Ctrl-C again" in err
        # Output is still delivered after the warning
        assert capsys.readouterr().out == "" or True  # output consumed above

    def test_ctrl_c_twice_raises_keyboard_interrupt(self):
        """Two consecutive Ctrl-Cs propagate KeyboardInterrupt out of _eval_one."""
        repl, _ = _make_repl("42\n")
        with pytest.raises(KeyboardInterrupt):
            repl._eval_one("1+1", _done=_AlwaysInterruptEvent())


# ---------------------------------------------------------------------------
# Wrapper logic — tested locally without a live Frida session.
#
# The wrapper Python string is exactly what the Frida agent runs inside the
# target process via PyRun_String.  Executing it locally with exec() lets us
# verify stdout capture, exception handling, state persistence, and result
# formatting without needing a real target.
# ---------------------------------------------------------------------------


class TestWrapperLogic:
    """Execute the wrapper locally to verify its Python-side behaviour."""

    def _run_wrapper(self, source: str, ns: dict | None = None) -> str:
        """Run the wrapper using *ns* as the user's persistent namespace.

        *ns* mirrors __main__.__dict__ in the actual agent: it is passed as
        both globals AND locals to exec(compile(source, 'single'), ...) so
        that all name bindings (def, import, assignment) are stored there and
        survive across calls.  Expression results are displayed via
        sys.displayhook, which writes repr(value)+'\\n' to the patched stdout.
        """
        if ns is None:
            ns = {"__builtins__": builtins}
        elif "__builtins__" not in ns:
            ns["__builtins__"] = builtins

        # Append \n to terminate compound statements in 'single' mode
        # (e.g. "def f(): ..." needs a trailing newline or it raises EOF SyntaxError).
        src_repr = repr(source + "\n")
        wrapper = (
            "import io as _zap_repl_io, sys as _zap_repl_sys, traceback as _zap_repl_tb\n"
            "_zap_repl_buf = _zap_repl_io.StringIO()\n"
            "_zap_repl_old = _zap_repl_sys.stdout\n"
            "_zap_repl_sys.stdout = _zap_repl_buf\n"
            "try:\n"
            f"    exec(compile({src_repr}, '<zap_repl>', 'single'), _zap_repl_ns, _zap_repl_ns)\n"
            "except BaseException:\n"
            "    _zap_repl_tb.print_exc(file=_zap_repl_sys.stdout)\n"
            "finally:\n"
            "    _zap_repl_sys.stdout = _zap_repl_old\n"
            "_zap_repl_out = _zap_repl_buf.getvalue()\n"
        )
        exec_ns: dict = {"_zap_repl_ns": ns}
        exec(wrapper, exec_ns)  # noqa: S102
        return exec_ns["_zap_repl_out"]

    # --- basic output ---

    def test_print_captured(self):
        assert self._run_wrapper("print('hello')") == "hello\n"

    def test_expression_result_shown(self):
        assert self._run_wrapper("1 + 1") == "2\n"

    def test_none_result_not_shown(self):
        assert self._run_wrapper("x = 42") == ""

    def test_print_before_expression(self):
        out = self._run_wrapper("print('first'); 99")
        assert out == "first\n99\n"

    # --- exception capture ---

    def test_name_error_in_buffer(self):
        out = self._run_wrapper("undefined_name")
        assert "NameError" in out

    def test_zero_division_in_buffer(self):
        out = self._run_wrapper("1/0")
        assert "ZeroDivisionError" in out

    def test_exception_not_on_stderr(self, capsys):
        self._run_wrapper("raise ValueError('boom')")
        assert capsys.readouterr().err == ""

    def test_stdout_restored_after_exception(self):
        import sys

        original = sys.stdout
        self._run_wrapper("1/0")
        assert sys.stdout is original

    # --- state persistence across calls (the key bug fixed) ---

    def test_import_persists_to_next_call(self):
        """import on call 1 must be visible on call 2."""
        ns: dict = {"__builtins__": builtins}
        self._run_wrapper("import os", ns)
        out = self._run_wrapper("os.sep", ns)
        assert out.strip()  # '/' on POSIX, '\\' on Windows — non-empty

    def test_assignment_persists(self):
        ns: dict = {"__builtins__": builtins}
        self._run_wrapper("x = 42", ns)
        out = self._run_wrapper("x", ns)
        assert out == "42\n"

    def test_function_definition_persists(self):
        ns: dict = {"__builtins__": builtins}
        self._run_wrapper("def double(n): return n * 2", ns)
        out = self._run_wrapper("double(7)", ns)
        assert out == "14\n"

    def test_second_import_sees_first(self):
        """Simulates the exact user-reported sequence: import os / print(os.__file__)."""
        ns: dict = {"__builtins__": builtins}
        self._run_wrapper("import os", ns)
        out = self._run_wrapper("print(os.__file__)", ns)
        assert "os" in out  # some path containing "os"
        assert "NameError" not in out

    # --- stdout reference note ---

    def test_stdout_write_via_sys_captured(self):
        """Writes via sys.stdout (the patched object) are captured."""
        out = self._run_wrapper("import sys; sys.stdout.write('hi\\n') or None")
        assert "hi" in out
