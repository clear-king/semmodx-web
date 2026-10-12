"""
Headless IDA worker for SemModX Web.

Started by worker_client.py as:

    <ida python> -u -I ida_worker.py <plugin_parent_dir>

Runs under `idalib` (IDA as a library) with no desktop UI. Holds one database
open and answers one JSON request per line on stdin, replying with one JSON
object per line on a dedicated protocol channel.

Two constraints shape this design:

1. idalib is single-threaded. Every IDA call must happen on the thread that
   initialized the library, so this process is a plain synchronous loop and the
   parent serializes its requests.

2. The SemModX code prints liberally (basicutils prints every address in .text,
   snap_cg prints every call-graph edge). That would corrupt a stdio protocol,
   so the real stdout is dup'd to a private handle for protocol traffic and
   fd 1 is repointed at stderr, which the parent sends to a log file.

3. LLM calls go through the plugin's own model layer (semmodx.config.model),
   so every provider the plugin supports works here too. That layer delivers
   results with ida_kernwin.execute_sync(), which needs a UI event loop that
   idalib does not have; the worker replaces it with a direct call.

Protocol replies: {"id": <n>, "ok": true, "val": ...}
             or: {"id": <n>, "ok": false, "err": "..."}
"""

import os
import re
import sys
import json
import time
import io
import traceback

# ---------------------------------------------------------------------------
# Protocol channel setup. Must happen before anything else can print.
#
# Everything here is explicitly UTF-8. On a Chinese Windows the console codepage
# is GBK (cp936), so the default TextIOWrapper for stdin/stdout would decode the
# JSON payload as GBK and silently corrupt every non-ASCII string (analysis
# results became lone surrogates, which idc.set_func_cmt then rejected with a
# TypeError). The protocol must never depend on the locale.
# ---------------------------------------------------------------------------
_proto_fd = os.dup(1)
os.dup2(2, 1)                 # fd1 -> stderr, so plugin print() lands in the log
PROTO = os.fdopen(_proto_fd, "w", buffering=1, encoding="utf-8", errors="replace")
STDIN = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace",
                         newline="\n")

if len(sys.argv) < 2:
    sys.stderr.write("usage: ida_worker.py <directory containing semmodx/>\n")
    sys.exit(2)
PLUGIN_PARENT = sys.argv[1]                          # so `import semmodx` resolves
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PLUGIN_PARENT)


def emit(obj):
    PROTO.write(json.dumps(obj, ensure_ascii=False) + "\n")
    PROTO.flush()


def log(*a):
    print("[worker]", *a, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# idalib must be the first IDA-related import in the process.
# ---------------------------------------------------------------------------
import idapro                                              # noqa: E402

idapro.enable_console_messages(False)


def _ensure_snap():
    """Use snap-stanford when installed; otherwise fall back to the bundled shim.

    PyPI also has an unrelated package called plain `snap` (a Zope helper) that
    imports fine but has no graph API, so "import succeeded" is not enough.
    """
    try:
        import snap
        if hasattr(snap, "PNGraph"):
            return "snap-stanford"
    except Exception:
        pass
    sys.path.insert(0, HERE)
    import snap_shim
    snap_shim.install()
    return "bundled shim (snap-stanford not installed)"


SNAP_BACKEND = _ensure_snap()

# The plugin's model layer hands results to the UI thread via execute_sync().
# There is no UI thread here, so run the callback inline.
import ida_kernwin                                         # noqa: E402

ida_kernwin.execute_sync = lambda fn, flags=0: fn()

log("idalib version:", idapro.get_library_version())
log("graph backend:", SNAP_BACKEND)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
STATE = {"path": None, "root": None, "opened_at": None}

_lfa = None
_bu = None
_snap_cg = None
_hexrays = None
_idc = None
_idautils = None
_ida_funcs = None
_ida_ida = None
_config = None


def load_plugin_modules():
    """Import the SemModX clustering modules. Deferred until a DB is open."""
    global _lfa, _bu, _snap_cg, _hexrays, _idc, _idautils, _ida_funcs, _ida_ida
    if _lfa is not None:
        return
    import idc
    import idautils
    import ida_funcs
    import ida_ida
    import ida_hexrays
    import semmodx.codecut.lfa as lfa
    import semmodx.codecut.basicutils_7x as basicutils
    import semmodx.codecut.snap_cg as snap_cg

    _lfa, _bu, _snap_cg = lfa, basicutils, snap_cg
    _hexrays, _idc, _idautils = ida_hexrays, idc, idautils
    _ida_funcs, _ida_ida = ida_funcs, ida_ida


# ---------------------------------------------------------------------------
# Ported from semmodx/ida/cluster_gui.py, which in turn takes this source-file
# string scan from IDAMagicStrings by Joxean Koret (GPL-3.0).
# ---------------------------------------------------------------------------
SOURCE_FILES_REGEXP = (
    r"([a-z_\/\\][a-z0-9_/\\:\-\.@]+\.(c|cc|cxx|c\+\+|cpp|h|hpp|m|rs|go|ml))($|:| )"
)
LANGS = {
    "C/C++": ["c", "cc", "cxx", "cpp", "h", "hpp"],
    "C": ["c"],
    "C++": ["cc", "cxx", "cpp", "hpp", "c++"],
    "Obj-C": ["m"],
    "Rust": ["rs"],
    "Golang": ["go"],
    "OCaml": ["ml"],
}


def get_lang(full_path):
    _, ext = os.path.splitext(full_path.lower())
    ext = ext.strip(".")
    for key in LANGS:
        if ext in LANGS[key]:
            return key
    return None


def get_source_strings(min_len=4, strtypes=(0, 1)):
    """Ported from cluster_gui.get_source_strings().

    Returns (mapping of ea -> module label, language statistics).
    The GUI version returns a larger structure; only the ea->label mapping is
    consumed by populate_tree(), so that is what this reproduces.
    """
    strings = _idautils.Strings()
    strings.setup(strtypes=list(strtypes))

    module_names = {}
    lang_counts = {}
    total_files = 0
    seen = set()

    for s in strings:
        if not s or s.length <= min_len:
            continue
        try:
            text = str(s)
        except Exception:
            continue
        if s.ea in seen:
            continue
        hit = re.findall(SOURCE_FILES_REGEXP, text, re.IGNORECASE)
        if not hit:
            continue
        refs = list(_idautils.DataRefsTo(s.ea))
        if not refs:
            continue
        seen.add(s.ea)
        total_files += 1
        full_path = hit[0][0]
        lang = get_lang(full_path)
        if lang:
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
        for ref in refs:
            module_names[ref] = text

    # Fall back to debug-info source paths when available.
    import ida_gdl

    for f in list(_idautils.Functions()):
        func = _ida_funcs.get_func(f)
        if func is None:
            continue
        try:
            cfg = ida_gdl.FlowChart(func)
        except Exception:
            continue
        stop = False
        for block in cfg:
            if stop:
                break
            for head in _idautils.Heads(block.start_ea, block.end_ea):
                try:
                    sp = _idc.get_sourcefile(head)
                except Exception:
                    sp = None
                if sp:
                    total_files += 1
                    lang = get_lang(sp)
                    if lang:
                        lang_counts[lang] = lang_counts.get(lang, 0) + 1
                    module_names[head] = "Symbol: %s" % sp
                    stop = True
                    break

    return module_names, {"total_files": total_files, "langs": lang_counts}


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def _arch_info():
    proc = bits = None
    try:
        proc = _ida_ida.inf_get_procname()
    except Exception:
        pass
    try:
        bits = 64 if _ida_ida.inf_is_64bit() else 32
    except Exception:
        pass
    return {"proc": proc, "bits": bits}


def cmd_open(req):
    path = req["path"]
    auto = bool(req.get("auto_analysis", True))

    # A database must be closed before another can be opened. Calling
    # open_database() while one is already loaded aborts the process outright
    # (the idalib kernel cannot re-init over a live database), which then looks
    # like an unrelated "error 4" on whatever file the user picked next.
    if STATE.get("path"):
        try:
            idapro.close_database(False)
        except Exception as e:
            log("close before reopen failed:", e)
        STATE["path"] = None
        STATE["root"] = None

    t = time.time()
    code = idapro.open_database(path, auto)
    if code != 0:
        return {
            "ok": False,
            "err": (
                "IDA refused to load this file (open_database returned %d). "
                "The usual cause is a processor module that is not licensed in "
                "this installation - IDA reports 'processor type X is not "
                "included in the installed version' in the worker log. A second "
                "possibility is that another process (such as the desktop IDA, "
                "or another copy of this frontend) already has the database "
                "open, since IDA locks it exclusively." % code
            ),
        }
    import ida_auto

    ida_auto.auto_wait()
    load_plugin_modules()
    STATE["path"] = path
    STATE["root"] = _idc.get_root_filename()
    STATE["opened_at"] = time.time()
    return {
        "ok": True,
        "val": {
            "path": path,
            "root": STATE["root"],
            "arch": _arch_info(),
            "open_secs": round(time.time() - t, 2),
        },
    }


def cmd_tree(req):
    """Rebuild the Object Files tree: LFA modules, each with its functions."""
    # lfa.analyze() appends to module-level globals and never clears them, so a
    # second call would duplicate every entry. Reset before each rebuild.
    _lfa.g_function_list = []
    _lfa.g_module_list = []

    module_names, stats = get_source_strings()

    t = time.time()
    _, lfa_modlist = _lfa.analyze()
    analyze_secs = round(time.time() - t, 2)

    tree = []
    used = {}
    for idx, md in enumerate(lfa_modlist):
        name = "\u6a21\u5757 0x%08x:0x%08x" % (md.start, md.end)
        for ea in module_names:
            if md.start <= ea <= md.end:
                name = module_names[ea]
                break
        # Keep colliding display names distinct as separate rows.
        if name in used:
            used[name] += 1
            name = "%s (%d)" % (name, used[name])
        else:
            used[name] = 1

        funcs = [
            {"ea": f, "name": _idc.get_func_name(f) or ("sub_%x" % f)}
            for f in _idautils.Functions(md.start, md.end)
        ]
        tree.append(
            {
                "idx": idx,
                "name": name,
                "start": md.start,
                "end": md.end,
                "size": md.end - md.start,
                "nfunctions": len(funcs),
                "functions": funcs,
            }
        )

    return {
        "ok": True,
        "val": {
            "modules": tree,
            "analyze_secs": analyze_secs,
            "stats": stats,
            "nfunctions": _ida_funcs.get_func_qty(),
        },
    }


def cmd_decompile(req):
    ea = int(req["ea"])
    f = _ida_funcs.get_func(ea)
    if f is None:
        return {"ok": False, "err": "no function at 0x%x" % ea}
    try:
        d = _hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"ok": False, "err": "decompile failed: %s" % e}
    if d is None:
        return {"ok": False, "err": "decompile returned nothing for 0x%x" % f.start_ea}
    return {"ok": True, "val": {"ea": f.start_ea, "code": str(d)}}


def cmd_get_comment(req):
    ea = int(req["ea"])
    kind = req.get("kind", "func")
    cmt = (_idc.get_func_cmt(ea, 0) if kind == "func" else _idc.get_cmt(ea, 0)) or ""
    if isinstance(cmt, bytes):
        cmt = cmt.decode("utf-8", "replace")
    return {"ok": True, "val": {"comment": str(cmt)}}


def cmd_set_comment(req):
    ea = int(req["ea"])
    text = req["text"]
    kind = req.get("kind", "func")
    ok = _idc.set_func_cmt(ea, text, 0) if kind == "func" else _idc.set_cmt(ea, text, 0)
    return {"ok": True, "val": {"set": bool(ok)}}


def cmd_rename_lvars(req):
    """Apply renames proposed by the model.

    Uses the free-function `ida_hexrays.rename_lvar`, which is the path IDA 9.0
    takes (the GUI code branches on IDA_SDK_VERSION >= 760 for exactly this).
    """
    ea = int(req["ea"])
    mapping = req.get("mapping") or {}
    f = _ida_funcs.get_func(ea)
    if f is None:
        return {"ok": False, "err": "no function at 0x%x" % ea}
    replaced, failed = [], []
    for old, new in mapping.items():
        try:
            if _hexrays.rename_lvar(f.start_ea, old, new):
                replaced.append([old, new])
            else:
                failed.append(old)
        except Exception:
            failed.append(old)
    return {"ok": True, "val": {"renamed": replaced, "failed": failed}}


def cmd_callgraph_order(req):
    """Order a module's functions so callees precede callers (snap_cg)."""
    start, end = int(req["start"]), int(req["end"])
    # create_snap_cg() reuses the module-global UGraph; reset for a clean build.
    _snap_cg.UGraph = _snap_cg.snap.PNGraph.New()
    cg = _snap_cg.create_snap_cg(start, end)
    order = _snap_cg.get_sorted_prompt_order(cg)
    out = []
    for a in order:
        f = _ida_funcs.get_func(a)
        if f is not None:
            out.append({"ea": f.start_ea, "name": _idc.get_func_name(f.start_ea)})
    return {
        "ok": True,
        "val": {"order": out, "nodes": cg.GetNodes(), "edges": cg.GetEdges()},
    }


def cmd_close(req):
    save = bool(req.get("save", False))
    try:
        idapro.close_database(save)
    except Exception as e:
        return {"ok": False, "err": str(e)}
    STATE["path"] = None
    return {"ok": True, "val": {"saved": save}}


def cmd_status(req):
    return {
        "ok": True,
        "val": {
            "path": STATE["path"],
            "root": STATE["root"],
            "loaded": _lfa is not None,
            "graph_backend": SNAP_BACKEND,
        },
    }


def _load_llm():
    """Load the plugin's config.ini and model, once. Errors are reported, not raised."""
    global _config
    if _config is None:
        import builtins
        if not hasattr(builtins, "_"):
            builtins._ = lambda s: s
        import semmodx.config as config
        # Capture the plugin's warning dialog text instead of trying to show it.
        warnings = []
        ida_kernwin.warning = lambda msg: warnings.append(msg)
        config.load_config()
        config._web_warnings = warnings
        _config = config
    return _config


def cmd_llm_status(req):
    config = _load_llm()
    import semmodx.models.model_manager as mm
    return {"ok": True, "val": {
        "model": mm.qualified_name(config.model),
        "configured": config.model is not None,
        "providers": [p.get_menu_name() for p in mm.list_models()],
        "config_path": config.CONFIG_PATH,
        "warnings": [_strip_title(w) for w in config._web_warnings],
    }}


def _strip_title(msg):
    # The plugin prefixes its dialog text with a "SemModX" title line.
    return msg[len("SemModX\n\n"):] if msg.startswith("SemModX\n\n") else msg


def cmd_llm(req):
    """One chat completion through the plugin's configured model."""
    config = _load_llm()
    if config.model is None:
        msg = config._web_warnings[-1] if config._web_warnings else "no model configured"
        return {"ok": False, "err": _strip_title(msg)}
    opts = {"response_format": {"type": "json_object"}} if req.get("json") else None
    box = {}
    # query_model is synchronous and swallows errors into print(); capture both.
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        config.model.query_model(req["messages"], lambda response: box.setdefault("r", response), opts)
    if "r" not in box:
        return {"ok": False, "err": buf.getvalue().strip() or "the model returned no response"}
    return {"ok": True, "val": {"reply": box["r"]}}


def cmd_echo_type(req):
    """Diagnostic: report how a payload string arrived (type/encoding)."""
    t = req.get("text")
    return {"ok": True, "val": {
        "type": type(t).__name__,
        "len": len(t) if t is not None else None,
        "repr": repr(t)[:200] if t is not None else None,
        "stdin_encoding": getattr(sys.stdin, "encoding", None),
        "stdin_is_binary": not hasattr(sys.stdin, "encoding"),
        "fs_encoding": sys.getfilesystemencoding(),
        "preferred": __import__("locale").getpreferredencoding(False),
        "stdout_encoding": getattr(sys.stdout, "encoding", None),
    }}


HANDLERS = {
    "echo": cmd_echo_type,
    "llm": cmd_llm,
    "llm_status": cmd_llm_status,
    "open": cmd_open,
    "tree": cmd_tree,
    "decompile": cmd_decompile,
    "get_comment": cmd_get_comment,
    "set_comment": cmd_set_comment,
    "rename_lvars": cmd_rename_lvars,
    "callgraph_order": cmd_callgraph_order,
    "close": cmd_close,
    "status": cmd_status,
}


def main():
    for line in STDIN:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            emit({"id": None, "ok": False, "err": "bad request json: %s" % e})
            continue
        rid = req.get("id")
        name = req.get("cmd")
        if name == "quit":
            emit({"id": rid, "ok": True, "val": "bye"})
            break
        fn = HANDLERS.get(name)
        if fn is None:
            emit({"id": rid, "ok": False, "err": "unknown command %r" % name})
            continue
        try:
            res = fn(req)
            res["id"] = rid
            emit(res)
        except Exception as e:
            emit(
                {
                    "id": rid,
                    "ok": False,
                    "err": "%s: %s" % (type(e).__name__, e),
                    "tb": traceback.format_exc().strip().splitlines()[-4:],
                }
            )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(traceback.format_exc(), file=sys.stderr, flush=True)
        sys.exit(1)
