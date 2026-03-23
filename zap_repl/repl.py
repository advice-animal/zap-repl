from __future__ import annotations

import os
import sys
import threading
from typing import TYPE_CHECKING, Any

try:
    import readline

    _HISTORY_FILE: str | None = os.path.expanduser("~/.zap_repl_history")
    try:
        readline.read_history_file(_HISTORY_FILE)
    except FileNotFoundError:
        pass
    readline.set_history_length(1000)
except ImportError:
    _HISTORY_FILE = None  # Windows

if TYPE_CHECKING:
    import frida

PROMPT = ">>> "

# Frida agent loaded once per REPL session.
#
# evalPython(source):
#   1. Acquires the Python GIL.
#   2. Runs `source` in __main__'s namespace (persistent state across calls).
#      sys.stdout is temporarily replaced with io.StringIO to capture output.
#   3. exec(compile(src, 'single'), ns, ns) is used:
#        - 'single' mode triggers sys.displayhook for expression results,
#          which writes repr(value)+'\n' to sys.stdout (our buffer).
#        - Same dict for globals AND locals ensures that def/import/assignment
#          all bind names in __main__.__dict__ and persist across calls.
#        - A trailing '\n' is appended to terminate compound statements
#          (e.g. "def f(): ..." needs it in 'single' mode).
#   4. Exceptions are caught inside the wrapper and written to the capture
#      buffer as tracebacks — they appear as remote output, not target stderr.
#   5. Returns {output: <str>}.
#
# Initialization is wrapped in try/catch so that if any Python C-API symbol
# is missing, rpc.exports is still set up and evalPython returns the error as
# output rather than destroying the script (which would show as the cryptic
# "script has been destroyed" error on the Python side).
#
# Note: output capture works for code that writes via sys.stdout.  Code that
# holds a reference to the original file object or uses lower-level write
# primitives (e.g. os.write(1, ...)) will bypass the redirect.
_AGENT_JS = r"""
(function () {
    'use strict';

    // Search all loaded modules for a Python C-API export.
    // Returns a NativePointer on success, null if not yet found.
    // Uses module-instance getExportByName (Frida 16+; the static
    // Module.findExportByName was removed in Frida 16).
    function sym(name) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            try {
                var p = mods[i].getExportByName(name);
                if (p !== null && !p.isNull()) return p;
            } catch (e) {}
        }
        return null;  // not found in any module yet
    }

    // Attempt to bind all Python C-API symbols.
    // Returns null on success, or an error string on the first failure.
    // A null return from sym() means "not yet loaded" (worth retrying);
    // a NativeFunction error means the pointer is genuinely wrong.
    var _initErr = null;
    var _GILEnsure, _GILRelease, _RunString, _DecRef,
        _ErrPrint, _ErrClear, _ImportAdd, _ModDict,
        _DictGet, _Utf8, _mainName, _outKey;

    var _symDefs = [
        ['PyGILState_Ensure',    'uint32',  [],                                       function(f) { _GILEnsure  = f; }],
        ['PyGILState_Release',   'void',    ['uint32'],                               function(f) { _GILRelease = f; }],
        ['PyRun_String',         'pointer', ['pointer', 'int', 'pointer', 'pointer'], function(f) { _RunString  = f; }],
        ['Py_DecRef',            'void',    ['pointer'],                              function(f) { _DecRef     = f; }],
        ['PyErr_Print',          'void',    [],                                       function(f) { _ErrPrint   = f; }],
        ['PyErr_Clear',          'void',    [],                                       function(f) { _ErrClear   = f; }],
        ['PyImport_AddModule',   'pointer', ['pointer'],                              function(f) { _ImportAdd  = f; }],
        ['PyModule_GetDict',     'pointer', ['pointer'],                              function(f) { _ModDict    = f; }],
        ['PyDict_GetItemString', 'pointer', ['pointer', 'pointer'],                  function(f) { _DictGet    = f; }],
        ['PyUnicode_AsUTF8',     'pointer', ['pointer'],                             function(f) { _Utf8       = f; }],
    ];

    function _tryInit() {
        for (var i = 0; i < _symDefs.length; i++) {
            var def = _symDefs[i], sname = def[0], ret = def[1], args = def[2], assign = def[3];
            var ptr = sym(sname);
            if (ptr === null) return 'symbol not yet loaded: ' + sname;
            try {
                assign(new NativeFunction(ptr, ret, args));
            } catch (e) {
                return 'NativeFunction(' + sname + ', ptr=' + ptr + '): ' + e.message;
            }
        }
        try {
            _mainName = Memory.allocUtf8String('__main__');
            _outKey   = Memory.allocUtf8String('_repl_out');
        } catch (e) {
            return 'Memory.allocUtf8String: ' + e.message;
        }
        return null;  // success
    }

    // Retry for up to 2 s in case the Python runtime dynamic library has not
    // finished loading when the agent first runs (common when spawning).
    var _deadline = Date.now() + 2000;
    while (true) {
        var _tryErr = _tryInit();
        if (_tryErr === null) break;
        if (Date.now() >= _deadline) {
            _initErr = 'repl agent init failed: ' + _tryErr + '\n';
            break;
        }
        Thread.sleep(0.1);
    }

    var FILE_INPUT = 257;

    function mainDict() {
        return _ModDict(_ImportAdd(_mainName));  // borrowed ref, valid for process lifetime
    }

    rpc.exports = {
        // Called once at startup to verify the agent is working and to fetch
        // the Python version banner for display on the host side.
        banner: function () {
            if (_initErr !== null) return {error: _initErr};
            var gstate = _GILEnsure();
            var result;
            try {
                var g    = mainDict();
                var code = Memory.allocUtf8String(
                    "import sys as _repl_sys\n" +
                    "__import__('__main__').__dict__['_repl_out'] = (\n" +
                    "    'Python %s on %s' % (_repl_sys.version, _repl_sys.platform)\n" +
                    ")\n"
                );
                var ret = _RunString(code, FILE_INPUT, g, g);
                if (ret.isNull()) {
                    _ErrPrint(); _ErrClear();
                    result = {error: 'could not read Python banner'};
                } else {
                    _DecRef(ret);
                    var outObj = _DictGet(g, _outKey);
                    var out = '';
                    if (!outObj.isNull()) {
                        var p = _Utf8(outObj);
                        if (!p.isNull()) out = p.readUtf8String();
                    }
                    result = {banner: out};
                }
            } catch (e) {
                result = {error: 'Frida error: ' + e.toString()};
            } finally {
                _GILRelease(gstate);
            }
            return result;
        },

        evalPython: function (source) {
            if (_initErr !== null) return {output: _initErr};

            // Pass __main__.__dict__ as BOTH globals and locals so that all
            // name bindings (def, import, =) go into __main__ and persist.
            // _repl_out is also stored there; we read and delete it afterward.
            var wrapper =
                "import io as _repl_io, sys as _repl_sys, traceback as _repl_tb\n" +
                "_repl_buf = _repl_io.StringIO()\n" +
                "_repl_old = _repl_sys.stdout\n" +
                "_repl_sys.stdout = _repl_buf\n" +
                "try:\n" +
                "    exec(compile(" + JSON.stringify(source + "\n") + ", '<repl>', 'single'), __import__('__main__').__dict__, __import__('__main__').__dict__)\n" +
                "except BaseException:\n" +
                "    _repl_tb.print_exc(file=_repl_sys.stdout)\n" +
                "finally:\n" +
                "    _repl_sys.stdout = _repl_old\n" +
                "__import__('__main__').__dict__['_repl_out'] = _repl_buf.getvalue()\n";

            var gstate = _GILEnsure();
            var result;
            try {
                var g    = mainDict();
                var code = Memory.allocUtf8String(wrapper);
                var ret  = _RunString(code, FILE_INPUT, g, g);
                if (ret.isNull()) {
                    // The wrapper itself raised — shouldn't happen since it
                    // catches BaseException, but guard anyway.
                    _ErrPrint();
                    _ErrClear();
                    result = {output: '[wrapper error — see target stderr]\n'};
                } else {
                    _DecRef(ret);
                    var outObj = _DictGet(g, _outKey);
                    var out = '';
                    if (!outObj.isNull()) {
                        var p = _Utf8(outObj);
                        if (!p.isNull()) out = p.readUtf8String();
                    }
                    result = {output: out};
                }
            } catch (e) {
                result = {output: 'Frida error: ' + e.toString() + '\n'};
            } finally {
                _GILRelease(gstate);
            }
            return result;
        }
    };
}());
"""


class Repl:
    def __init__(self, session: frida.core.Session, *, prefix: bool = False) -> None:
        self._session = session
        self._prefix = prefix
        self._agent: frida.core.Script | None = None

    def _ensure_agent(self) -> frida.core.Script:
        if self._agent is None:
            agent = self._session.create_script(_AGENT_JS)

            # Surface any Frida-level script errors (e.g. JS syntax errors)
            # so they aren't swallowed silently.
            def _on_message(msg: dict[str, Any], _data: bytes | None) -> None:
                if msg.get("type") == "error":
                    desc = msg.get("description") or str(msg)
                    print(f"[agent error: {desc}]", file=sys.stderr)

            agent.on("message", _on_message)  # type: ignore[call-overload]
            agent.load()
            self._agent = agent
        return self._agent

    def _eval_one(
        self,
        source: str,
        *,
        _done: threading.Event | None = None,
    ) -> None:
        agent = self._ensure_agent()
        result_box: list[dict[str, Any]] = []
        exc_box: list[Exception] = []
        done = _done if _done is not None else threading.Event()

        def rpc_call() -> None:
            try:
                result_box.append(agent.exports_sync.eval_python(source))
            except Exception as exc:
                exc_box.append(exc)
            finally:
                done.set()

        threading.Thread(target=rpc_call, daemon=True).start()

        # Wait for the RPC to complete.  The remote Python code may be holding
        # the GIL, so we cannot safely abandon the call — we must wait for it
        # to finish.  On the first Ctrl-C we warn the user and keep waiting;
        # on a second Ctrl-C we raise KeyboardInterrupt to exit the REPL.
        warned = False
        while True:
            try:
                if done.wait(timeout=0.5):
                    break
            except KeyboardInterrupt:
                if warned:
                    raise  # second Ctrl-C: give up
                print(
                    "\n[remote is still executing — Ctrl-C again to exit]",
                    file=sys.stderr,
                )
                warned = True

        if exc_box:
            raise exc_box[0]

        output = result_box[0].get("output", "")
        if output:
            for line in output.splitlines():
                print(f"remote: {line}" if self._prefix else line)

    def run_cmd(self, source: str) -> None:
        """Run one statement and print its output; no banner, no REPL loop."""
        try:
            agent = self._ensure_agent()
        except Exception as exc:
            print(f"[could not load agent: {exc}]", file=sys.stderr)
            return
        try:
            # Surface init errors the same way run() does.
            probe = agent.exports_sync.banner()
        except Exception as exc:
            print(f"[could not contact agent: {exc}]", file=sys.stderr)
            return
        if "error" in probe:
            print(f"[{probe['error'].rstrip()}]", file=sys.stderr)
            return
        try:
            self._eval_one(source)
        except Exception as exc:
            print(f"[detached: {exc}]", file=sys.stderr)

    def run(self) -> None:
        try:
            agent = self._ensure_agent()
        except Exception as exc:
            print(f"[could not load agent: {exc}]", file=sys.stderr)
            return

        # Run a startup probe: fetches the Python version banner and surfaces
        # any initialisation errors before the user types anything.
        try:
            probe = agent.exports_sync.banner()
        except Exception as exc:
            print(f"[could not contact agent: {exc}]", file=sys.stderr)
            return
        if "error" in probe:
            print(f"[{probe['error'].rstrip()}]", file=sys.stderr)
            return
        print(probe.get("banner", ""))

        while True:
            try:
                line = input(PROMPT)
            except EOFError:
                print()
                break
            except KeyboardInterrupt:
                # Ctrl-C at an empty prompt exits the REPL.
                print()
                break
            if not line.strip():
                continue
            try:
                self._eval_one(line)
            except KeyboardInterrupt:
                print()
                break  # second Ctrl-C while waiting for remote: exit cleanly
            except Exception as exc:
                print(f"[detached: {exc}]", file=sys.stderr)
                break

        if self._agent is not None:
            try:
                self._agent.unload()
            except Exception:
                pass

        if _HISTORY_FILE is not None:
            try:
                readline.write_history_file(_HISTORY_FILE)
            except OSError:
                pass
