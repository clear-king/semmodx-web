"""
FastAPI backend for the SemModX "Object Files" web frontend.

Serves the module tree that the desktop plugin shows in its Object Files
window, plus the per-module analysis and joint-rename operations, all backed by
a headless idalib worker (see core/ida_worker.py).

The bind address is configured in settings.ini. The databases contain the
entirety of whatever binary is under analysis, so keep the service restricted
to trusted clients.

Run:  python serve.py
      -> the URL configured in [server]
"""

import os
import re
import json
import time
import queue
import logging
import threading

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from .settings import get_settings
from .worker_client import get_worker, WorkerError
from . import prompts

HERE = os.path.dirname(os.path.abspath(__file__))
SETTINGS = get_settings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("web")

WORKSPACE = SETTINGS.workspace
os.makedirs(WORKSPACE, exist_ok=True)

app = FastAPI(title="SemModX Object Files", docs_url="/api/docs")


# ---------------------------------------------------------------------------
# Job registry: long-running LLM work, streamed to the browser over SSE
# ---------------------------------------------------------------------------
class Job(object):
    def __init__(self, kind, label):
        self.id = "%d-%d" % (int(time.time()), id(self) % 100000)
        self.kind = kind
        self.label = label
        self.q = queue.Queue()
        self.done = False
        self.result = None
        self.started = time.time()

    def emit(self, event, **data):
        self.q.put(dict(event=event, **data))

    def log(self, msg, level="info"):
        self.emit("log", level=level, msg=msg, ts=time.time())

    def finish(self, result=None):
        self.result = result
        self.done = True
        self.emit("end", result=result)


JOBS = {}
JOBS_LOCK = threading.Lock()


def new_job(kind, label):
    j = Job(kind, label)
    with JOBS_LOCK:
        JOBS[j.id] = j
    return j


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class OpenRequest(BaseModel):
    path: str
    auto_analysis: bool = True


class JobStartRequest(BaseModel):
    start: int
    end: int
    module_name: str
    limit: int = 0          # 0 = all functions


class RenameStartRequest(JobStartRequest):
    apply: bool = False     # False = dry run, propose only


# ---------------------------------------------------------------------------
# Database discovery
# ---------------------------------------------------------------------------
DB_EXT = (".i64", ".idb", ".i32", ".til")


def discover_databases(extra_dirs=()):
    """Find already-analysed databases to offer in the picker.

    Only existing .i64/.idb files are listed: the requested workflow is
    "reuse existing databases", not "analyse anything on disk".
    """
    found = []
    dirs = [WORKSPACE] + list(SETTINGS.database_dirs)
    dirs.extend(extra_dirs)

    seen = set()
    upload_root = os.path.normcase(os.path.abspath(SETTINGS.upload_dir))
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if not name.lower().endswith(DB_EXT):
                continue
            p = os.path.join(d, name)
            # Databases IDA creates next to uploaded binaries are reachable via
            # the upload list; skip them here so they do not show up twice.
            if os.path.normcase(os.path.abspath(p)).startswith(upload_root):
                continue
            if p in seen:
                continue
            seen.add(p)
            try:
                st = os.stat(p)
            except OSError:
                continue
            found.append({
                "path": p,
                "name": name,
                "dir": d,
                "size": st.st_size,
                "mtime": st.st_mtime,
            })
    found.sort(key=lambda x: x["mtime"], reverse=True)
    return found


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    with open(os.path.join(HERE, "static", "index.html"), encoding="utf-8") as f:
        return f.read()


@app.get("/api/databases")
def api_databases():
    return {"databases": discover_databases(), "workspace": WORKSPACE}


@app.get("/api/status")
def api_status():
    try:
        st = get_worker().call("status", timeout=30)
    except WorkerError as e:
        st = {"path": None, "root": None, "error": str(e)}
    try:
        st["llm"] = get_worker().call("llm_status", timeout=60)
    except WorkerError as e:
        st["llm"] = {"model": None, "configured": False, "warnings": [str(e)]}
    st["worker_log"] = get_worker().log_path
    return st


@app.post("/api/open")
def api_open(req: OpenRequest):
    if not os.path.exists(req.path):
        raise HTTPException(404, "no such file: %s" % req.path)
    try:
        # Opening a fresh database runs full auto-analysis and can take minutes.
        return get_worker().call("open", path=req.path,
                                 auto_analysis=req.auto_analysis, timeout=3600)
    except WorkerError as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# Binary upload
#
# Uploaded binaries are untrusted input and are treated as such: the client
# filename is discarded except for its extension, the file is written into a
# dedicated per-upload directory under workspace/, and nothing is ever executed
# or imported from there. IDA itself is the only thing that reads it, and IDA
# parses binaries for a living.
# ---------------------------------------------------------------------------
UPLOAD_ROOT = SETTINGS.upload_dir
MAX_UPLOAD = SETTINGS.max_upload_mb * 1024 * 1024

# Extension -> kept only to help IDA pick a loader; it also decides the suffix.
ALLOWED_EXT = {
    ".exe", ".dll", ".sys", ".ocx", ".scr", ".efi", ".bin", ".com",
    ".elf", ".so", ".o", ".a", ".ko", ".axf", ".out", ".prx",
    ".dylib", ".macho", ".dex", ".class", ".jar", ".apk",
    ".hex", ".ihex", ".srec", ".mot", ".rom", ".img", ".fw",
    ".wasm", ".pyc", ".vxd", ".drv",
}


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    raw_name = file.filename or "upload.bin"
    ext = os.path.splitext(raw_name)[1].lower()

    # Keep the extension only; never trust the client's directory components.
    # Extensionless files (common for Linux ELF) are fine: IDA identifies the
    # format from content, not from the name.
    if ext and ext not in ALLOWED_EXT:
        raise HTTPException(
            400, "不支持的文件类型 %r。支持的扩展名：%s"
                 % (ext or "(无)", ", ".join(sorted(ALLOWED_EXT))))

    stem = re.sub(r"[^A-Za-z0-9_.-]", "_",
                  os.path.splitext(os.path.basename(raw_name))[0])[:60] or "upload"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    subdir = os.path.join(UPLOAD_ROOT, "%s-%s" % (stamp, stem))
    os.makedirs(subdir, exist_ok=True)

    dest = os.path.join(subdir, stem + ext)
    # Avoid clobbering if the same name lands twice in one second.
    n = 1
    while os.path.exists(dest):
        dest = os.path.join(subdir, "%s_%d%s" % (stem, n, ext))
        n += 1

    started = time.time()
    try:
        with open(dest, "wb") as out:
            total = 0
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD:
                    raise ValueError("file exceeds the %d MiB limit"
                                     % (MAX_UPLOAD // (1024 * 1024)))
                out.write(chunk)
    except ValueError as e:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise HTTPException(413, str(e))
    except Exception as e:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise HTTPException(500, "写入失败: %s" % e)

    log.info("uploaded %s -> %s (%d bytes in %.1fs)",
             raw_name, dest, total, time.time() - started)

    return {
        "ok": True,
        "path": dest,
        "name": os.path.basename(dest),
        "size": total,
        "seconds": round(time.time() - started, 2),
        "note": "上传完成。点击「打开」会让 IDA 载入并自动分析，"
                "首次分析可能需要一段时间。",
    }


IDA_SIDECAR_EXT = (".id0", ".id1", ".id2", ".nam", ".til", ".i64", ".idb",
                   ".i32", ".$$$", ".dmp")


@app.get("/api/uploads")
def api_uploads():
    """List previously uploaded binaries so they can be re-opened.

    IDA writes its database files next to the binary it opens. Those are not
    listed as separate entries; instead, when a finished .i64 exists, the entry
    points at it so re-opening reuses the analysis instead of redoing it.
    """
    out = []
    if os.path.isdir(UPLOAD_ROOT):
        for dirpath, _dirnames, filenames in os.walk(UPLOAD_ROOT):
            names = set(filenames)
            for fn in filenames:
                if fn.lower().endswith(IDA_SIDECAR_EXT):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                db = None
                for cand in (fn + ".i64", os.path.splitext(fn)[0] + ".i64"):
                    if cand in names:
                        db = os.path.join(dirpath, cand)
                        break
                out.append({"path": db or p, "binary": p, "name": fn,
                            "size": st.st_size, "mtime": st.st_mtime,
                            "analysed": db is not None,
                            "dir": os.path.basename(dirpath)})
    out.sort(key=lambda x: x["mtime"], reverse=True)
    return {"uploads": out, "root": UPLOAD_ROOT}


@app.get("/api/tree")
def api_tree():
    try:
        return get_worker().call("tree", timeout=1800)
    except WorkerError as e:
        msg = str(e)
        if "no database" in msg.lower() or "not open" in msg.lower():
            raise HTTPException(409, "还没有打开数据库，请先点击「打开」。")
        raise HTTPException(500, msg)


@app.get("/api/decompile")
def api_decompile(ea: int):
    try:
        return get_worker().call("decompile", ea=ea, timeout=300)
    except WorkerError as e:
        raise HTTPException(500, str(e))


@app.get("/api/comment")
def api_comment(ea: int, kind: str = "func"):
    try:
        return get_worker().call("get_comment", ea=ea, kind=kind, timeout=60)
    except WorkerError as e:
        raise HTTPException(500, str(e))


@app.get("/api/callgraph")
def api_callgraph(start: int, end: int):
    try:
        return get_worker().call("callgraph_order", start=start, end=end, timeout=900)
    except WorkerError as e:
        raise HTTPException(500, str(e))


# ---------------------------------------------------------------------------
# SSE plumbing
# ---------------------------------------------------------------------------
def sse(job):
    """Yield a job's events as Server-Sent Events until it ends."""
    # Replay anything already queued, then follow live.
    while True:
        try:
            ev = job.q.get(timeout=0.5)
        except queue.Empty:
            if job.done and job.q.empty():
                break
            yield ": keepalive\n\n"
            continue
        yield "data: %s\n\n" % json.dumps(ev, ensure_ascii=False)
        if ev.get("event") == "end":
            break


@app.get("/api/job/{job_id}/stream")
def api_job_stream(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "no such job")
    return StreamingResponse(sse(job), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})


def ask_model(messages, json_mode=False):
    """One chat turn through the plugin's configured model, inside the worker."""
    return get_worker().call("llm", messages=messages, json=json_mode, timeout=600)["reply"]


def model_label():
    try:
        st = get_worker().call("llm_status", timeout=60)
    except WorkerError as e:
        raise RuntimeError(str(e))
    if not st.get("configured"):
        raise RuntimeError("; ".join(st.get("warnings") or ["no model configured in the plugin's config.ini"]))
    return st["model"]


# ---------------------------------------------------------------------------
# Module analysis (the "分析模块" button)
# ---------------------------------------------------------------------------
def run_module_analysis(job, start, end, module_name, limit):
    try:
        job.log("Building call graph order for module %s" % module_name)
        cg = get_worker().call("callgraph_order", start=start, end=end, timeout=1800)
        order = cg["order"]
        job.log("Call graph: %d nodes, %d edges; %d functions ordered"
                % (cg["nodes"], cg["edges"], len(order)))
        if limit:
            order = order[:limit]
            job.log("Limiting to first %d functions" % limit)

        job.log("Using model %s" % model_label())

        messages = [{"role": "system",
                     "content": prompts.module_analysis_system_prompt(module_name)}]
        total = len(order)
        summaries = []

        for i, f in enumerate(order, 1):
            ea, name = f["ea"], f["name"] or ("sub_%x" % f["ea"])
            job.emit("progress", i=i, total=total, ea=ea, name=name)
            try:
                d = get_worker().call("decompile", ea=ea, timeout=300)
                decomp = d["code"]
            except WorkerError as e:
                job.log("decompile failed for %s (0x%x): %s" % (name, ea, e), "warn")
                continue

            prompt = prompts.function_analysis_prompt(name, ea, decomp)
            messages.append({"role": "user", "content": prompt})
            try:
                reply = ask_model(messages)
            except WorkerError as e:
                job.log("model error on %s: %s" % (name, e), "error")
                messages.pop()
                continue

            messages.append({"role": "assistant", "content": reply})
            summaries.append((name, ea, reply))
            job.emit("function", ea=ea, name=name, reply=reply.strip())

            # Persist to the database immediately, so partial progress survives.
            try:
                cur = get_worker().call("get_comment", ea=ea, timeout=60)
                newc = prompts.build_decorated_comment(module_name, name, reply,
                                                   cur.get("comment", ""))
                get_worker().call("set_comment", ea=ea, text=newc, timeout=60)
            except WorkerError as e:
                job.log("could not write comment for %s: %s" % (name, e), "warn")

        # Module-level summary
        summary = None
        if summaries:
            job.log("Generating module summary from %d analyses" % len(summaries))
            messages.append({"role": "user",
                             "content": prompts.module_summary_prompt(module_name,
                                                                  len(summaries))})
            try:
                summary = ask_model(messages)
            except WorkerError as e:
                job.log("summary failed: %s" % e, "error")
            if summary:
                job.emit("summary", module=module_name, reply=summary.strip())
                try:
                    txt = prompts.build_module_summary_comment(module_name, summary)
                    get_worker().call("set_comment", ea=start, text=txt,
                                      kind="addr", timeout=60)
                    job.log("Module summary written at module start 0x%x" % start)
                except WorkerError as e:
                    job.log("could not write summary comment: %s" % e, "warn")
        job.finish({"analysed": len(summaries), "total": total,
                    "summary": summary})
    except Exception as e:
        job.log("job failed: %s" % e, "error")
        job.finish({"error": str(e)})


@app.post("/api/analyze_module")
def api_analyze_module(req: JobStartRequest):
    job = new_job("analyze", req.module_name)
    threading.Thread(
        target=run_module_analysis,
        args=(job, req.start, req.end, req.module_name, req.limit),
        daemon=True,
    ).start()
    return {"job_id": job.id}


# ---------------------------------------------------------------------------
# Joint rename (the "联合重命名" button)
# ---------------------------------------------------------------------------
def run_joint_rename(job, start, end, module_name, limit, apply_changes):
    try:
        cg = get_worker().call("callgraph_order", start=start, end=end, timeout=1800)
        order = cg["order"]
        job.log("Ordered %d functions from a %d-node call graph"
                % (len(order), cg["nodes"]))
        if limit:
            order = order[:limit]

        job.log("Using model %s (apply=%s)" % (model_label(), apply_changes))

        messages = [{"role": "system",
                     "content": prompts.rename_system_prompt(module_name)}]
        total = len(order)
        applied_total = 0

        for i, f in enumerate(order, 1):
            ea, name = f["ea"], f["name"] or ("sub_%x" % f["ea"])
            job.emit("progress", i=i, total=total, ea=ea, name=name)
            try:
                d = get_worker().call("decompile", ea=ea, timeout=300)
                decomp = d["code"]
            except WorkerError as e:
                job.log("decompile failed for %s: %s" % (name, e), "warn")
                continue

            prompt = prompts.rename_user_prompt(module_name, name, ea, decomp,
                                            first=(i == 1), index=i, total=total)
            messages.append({"role": "user", "content": prompt})
            try:
                reply = ask_model(messages, json_mode=True)
            except WorkerError as e:
                job.log("model error on %s: %s" % (name, e), "error")
                messages.pop()
                continue
            messages.append({"role": "assistant", "content": reply})

            mapping = prompts.parse_rename_json(reply)
            if not mapping:
                job.log("no usable renames for %s" % name, "warn")
                job.emit("rename", ea=ea, name=name, proposed={}, applied=[])
                continue

            applied = []
            if apply_changes:
                try:
                    res = get_worker().call("rename_lvars", ea=ea, mapping=mapping,
                                            timeout=300)
                    applied = res.get("renamed", [])
                    applied_total += len(applied)
                except WorkerError as e:
                    job.log("rename failed for %s: %s" % (name, e), "error")
            job.emit("rename", ea=ea, name=name, proposed=mapping, applied=applied)

        job.finish({"functions": total, "renamed": applied_total,
                    "applied": apply_changes})
    except Exception as e:
        job.log("job failed: %s" % e, "error")
        job.finish({"error": str(e)})


@app.post("/api/joint_rename")
def api_joint_rename(req: RenameStartRequest):
    job = new_job("rename", req.module_name)
    threading.Thread(
        target=run_joint_rename,
        args=(job, req.start, req.end, req.module_name, req.limit, req.apply),
        daemon=True,
    ).start()
    return {"job_id": job.id}


@app.get("/api/job/{job_id}")
def api_job_status(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "no such job")
    return {"id": job.id, "kind": job.kind, "done": job.done,
            "result": job.result, "elapsed": round(time.time() - job.started, 1)}


@app.post("/api/close")
def api_close(save: bool = False):
    try:
        return get_worker().call("close", save=save, timeout=600)
    except WorkerError as e:
        raise HTTPException(500, str(e))


@app.on_event("shutdown")
def _shutdown():
    try:
        get_worker().shutdown()
    except Exception:
        pass
