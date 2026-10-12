"""
Launcher for SemModX Web.

    python serve.py

Reads settings.ini next to this file, checks the environment, then serves the
web UI (http://127.0.0.1:6001 by default).
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def preflight(cfg):
    """Fail loudly and early rather than deep inside a request."""
    ok = True
    for problem in cfg.problems():
        print("!! " + problem)
        ok = False

    activation = os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro", "ida-config.json") \
        if os.name == "nt" else os.path.expanduser("~/.idapro/ida-config.json")
    if not os.path.isfile(activation):
        print("!! idalib is not activated (%s is missing). Run once:" % activation)
        print('     "%s" "%s"' % (cfg.python, os.path.join(cfg.ida_dir, "idalib", "python", "py-activate-idalib.py")))
        ok = False

    try:
        import fastapi, uvicorn, multipart  # noqa: F401
    except ImportError as e:
        print("!! missing web dependency: %s  ->  pip install -r requirements.txt" % e)
        ok = False

    if cfg.host not in ("127.0.0.1", "localhost", "::1"):
        print("** WARNING: [server] host = %s exposes the analysed binaries and the upload" % cfg.host)
        print("   endpoint to the network. There is no authentication.")
    return ok


if __name__ == "__main__":
    from semmodx_web.settings import get_settings, SettingsError

    try:
        cfg = get_settings()
    except SettingsError as e:
        print("!! " + str(e))
        sys.exit(1)
    if not preflight(cfg):
        sys.exit(1)

    import uvicorn

    print("=" * 62)
    print("  SemModX Web  -  headless IDA frontend")
    print("  http://%s:%d" % (cfg.host, cfg.port))
    print("  Ctrl+C to stop")
    print("=" * 62)
    uvicorn.run("semmodx_web.app:app", host=cfg.host, port=cfg.port, log_level="info", app_dir=ROOT)
