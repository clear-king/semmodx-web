"""
Parent-side supervisor for the headless IDA worker.

Owns exactly one worker subprocess. Everything that needs IDA funnels through
here, and a single lock serializes it, because idalib can only be driven from
the thread that loaded it.

The worker is started lazily and restarted if it dies.
"""

import os
import io
import json
import atexit
import logging
import subprocess
import threading

from .settings import get_settings, PROJECT_ROOT

log = logging.getLogger("idaworker")

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(HERE, "ida_worker.py")


class WorkerError(RuntimeError):
    """Raised when the worker cannot serve a request."""


class IdaWorker(object):
    def __init__(self):
        self._proc = None
        self._lock = threading.RLock()
        self._next_id = 0
        self._log_fh = None
        self._log_path = None

    # -- process lifecycle -------------------------------------------------
    def _spawn(self):
        cfg = get_settings()
        os.makedirs(cfg.log_dir, exist_ok=True)
        self._log_path = os.path.join(cfg.log_dir, "ida_worker.log")
        # Append so the log survives worker restarts within one session.
        self._log_fh = open(self._log_path, "ab", buffering=0)

        env = dict(os.environ)
        # idapro refuses to load inside an interactive IDA session's environment.
        env.pop("IDA_IS_INTERACTIVE", None)

        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        self._proc = subprocess.Popen(
            [cfg.python, "-u", "-I", WORKER, cfg.plugin_parent],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log_fh,
            cwd=PROJECT_ROOT,
            env=env,
            creationflags=creationflags,
            bufsize=0,
        )
        # The worker speaks UTF-8 on its protocol channel regardless of the
        # console codepage (GBK on Chinese Windows). Reading through this
        # wrapper keeps non-ASCII payloads intact.
        self._out = io.TextIOWrapper(self._proc.stdout, encoding="utf-8",
                                     errors="replace")
        log.info("worker started pid=%s log=%s", self._proc.pid, self._log_path)

    def _alive(self):
        return self._proc is not None and self._proc.poll() is None

    def ensure(self):
        with self._lock:
            if not self._alive():
                self._spawn()

    def shutdown(self):
        with self._lock:
            if self._proc is None:
                return
            try:
                if self._proc.poll() is None:
                    self._proc.stdin.write(b'{"cmd":"quit","id":0}\n')
                    self._proc.stdin.flush()
                    self._proc.wait(timeout=10)
            except Exception:
                pass
            try:
                if self._proc.poll() is None:
                    self._proc.kill()
            except Exception:
                pass
            self._proc = None
            if self._log_fh:
                try:
                    self._log_fh.close()
                except Exception:
                    pass
                self._log_fh = None

    # -- request/response --------------------------------------------------
    def _read_reply(self, want_id, timeout):
        """Read protocol lines until the reply for want_id arrives.

        The read happens on a helper thread so the timeout is real: a bare
        blocking readline() would sit forever if the worker wedged, which is
        exactly what happened when a bad payload made it raise before replying.

        Lines that are not valid JSON are ignored: plugin print() traffic is
        redirected to stderr, but a stray write to the original stdout handle
        should not desynchronize the protocol.
        """
        box = {}

        def reader():
            try:
                while True:
                    line = self._out.readline()
                    if not line:
                        box["eof"] = True
                        return
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        obj = json.loads(text)
                    except Exception:
                        continue
                    if obj.get("id") == want_id:
                        box["reply"] = obj
                        return
            except Exception as e:      # pragma: no cover - defensive
                box["exc"] = e

        t = threading.Thread(target=reader, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            # The worker is wedged or still busy. Kill it so the next request
            # starts from a clean process rather than hanging forever.
            self._kill()
            raise WorkerError(
                "timeout after %.0fs waiting for reply #%d (worker restarted)"
                % (timeout, want_id))
        if "exc" in box:
            raise WorkerError("protocol error: %s" % box["exc"])
        if "eof" in box:
            raise WorkerError("worker exited unexpectedly (see %s)" % self._log_path)
        return box["reply"]

    def _kill(self):
        try:
            if self._proc and self._proc.poll() is None:
                self._proc.kill()
                self._proc.wait(timeout=5)
        except Exception:
            pass

    def call(self, cmd, timeout=600, **kwargs):
        """Send one command and block for its reply. Serialized by a lock."""
        with self._lock:
            self.ensure()
            self._next_id += 1
            rid = self._next_id
            payload = dict(kwargs)
            payload["cmd"] = cmd
            payload["id"] = rid
            try:
                self._proc.stdin.write(
                    (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
                )
                self._proc.stdin.flush()
            except Exception as e:
                raise WorkerError("could not write to worker: %s" % e)

            reply = self._read_reply(rid, timeout)
            if not reply.get("ok"):
                raise WorkerError(reply.get("err") or "unknown worker error")
            return reply.get("val")

    @property
    def log_path(self):
        return self._log_path


WORKER_SINGLETON = IdaWorker()


def get_worker():
    return WORKER_SINGLETON


@atexit.register
def _cleanup():
    try:
        WORKER_SINGLETON.shutdown()
    except Exception:
        pass
