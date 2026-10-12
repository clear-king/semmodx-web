"""
Upload endpoint test against a running server.

    python tests/upload_test.py <some binary IDA can load> [server URL]

Checks: a normal upload, a rejected extension, a path-traversal filename,
an extensionless file, that uploads stay out of the database list, and that
an uploaded binary opens and builds a module tree.
"""
import json
import os
import sys
import uuid
import urllib.error
import urllib.request

if len(sys.argv) < 2 or not os.path.isfile(sys.argv[1]):
    sys.exit("usage: python tests/upload_test.py <binary> [http://127.0.0.1:6001]")
SAMPLE = sys.argv[1]
BASE = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:6001"
results = []


def check(name, cond, detail=""):
    results.append(("PASS" if cond else "FAIL", name, detail))


def post_file(data, filename):
    """Minimal multipart/form-data POST (no requests dependency)."""
    boundary = "----semmodx" + uuid.uuid4().hex
    body = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n") % (boundary, filename)).encode("utf-8") \
        + data + ("\r\n--%s--\r\n" % boundary).encode("utf-8")
    req = urllib.request.Request(BASE + "/api/upload", data=body,
                                 headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"detail": raw[:200]}


def call(path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method="POST" if data is not None else "GET",
                                 headers={"Content-Type": "application/json"} if data is not None else {})
    with urllib.request.urlopen(req, timeout=1800) as r:
        return json.loads(r.read().decode("utf-8"))


with open(SAMPLE, "rb") as fh:
    blob = fh.read()
name = os.path.basename(SAMPLE)

st, r = post_file(blob, name)
check("normal upload", st == 200 and r.get("ok"), r.get("path"))
uploaded = r.get("path")

st, r = post_file(b"not a binary", "notes.txt")
check("disallowed extension rejected", st == 400, r.get("detail", "")[:60])

st, r = post_file(blob, r"..\..\..\Windows\System32\evil.elf")
upload_root = call("/api/uploads")["root"]
check("path traversal neutralised", st == 200 and os.path.abspath(r["path"]).startswith(os.path.abspath(upload_root)),
      r.get("path"))

st, r = post_file(blob, "noext_binary")
check("extensionless accepted", st == 200 and r.get("ok"), r.get("path"))

dbs = call("/api/databases")["databases"]
check("uploads not listed as databases",
      not any(os.path.abspath(d["path"]).startswith(os.path.abspath(upload_root)) for d in dbs))

o = call("/api/open", {"path": uploaded, "auto_analysis": True})
t = call("/api/tree")
check("uploaded binary opens", bool(o.get("root")), "%s %s" % (o.get("root"), o.get("arch")))
check("module tree built", len(t["modules"]) > 0, "%d modules, %d funcs" % (len(t["modules"]), t["nfunctions"]))
call("/api/close?save=false", {})

for res in results:
    print("%-4s %-34s %s" % res)
print("%d/%d passed" % (sum(r[0] == "PASS" for r in results), len(results)))
print("Note: this test leaves its uploads under %s" % upload_root)
sys.exit(0 if all(r[0] == "PASS" for r in results) else 1)
