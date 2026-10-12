"""
End-to-end smoke test against a running server.

    python serve.py            # in one terminal
    python tests/smoke_test.py # in another

Opens the first database listed by /api/databases, builds the module tree,
builds one call graph, and runs "analyze module" on one function (this makes
one real model request through the plugin's config.ini).
"""
import sys
import json, time, uuid, urllib.request
B = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:6001"
out = []
def rec(k, v): out.append("%-28s %s" % (k, v))
def call(p, body=None, t=1800):
    d = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(B + p, data=d, method="POST" if d is not None else "GET",
                               headers={"Content-Type": "application/json"} if d is not None else {})
    with urllib.request.urlopen(r, timeout=t) as resp:
        return json.loads(resp.read().decode("utf-8"))
try:
    rec("index", urllib.request.urlopen(B + "/", timeout=30).status)
    st = call("/api/status")
    rec("graph backend", st.get("graph_backend"))
    rec("llm model", st["llm"].get("model"))
    rec("llm providers", st["llm"].get("providers"))
    dbs = call("/api/databases")["databases"]
    rec("databases found", [d["name"] for d in dbs])
    o = call("/api/open", {"path": dbs[0]["path"], "auto_analysis": True})
    rec("open", "%s %s" % (o["root"], o["arch"]))
    t = call("/api/tree")
    rec("tree", "%d modules, %d funcs" % (len(t["modules"]), t["nfunctions"]))
    m = min((x for x in t["modules"] if x["nfunctions"] >= 2), key=lambda x: x["nfunctions"])
    cg = call("/api/callgraph?start=%d&end=%d" % (m["start"], m["end"]))
    rec("callgraph", "%d nodes %d edges" % (cg["nodes"], cg["edges"]))
    j = call("/api/analyze_module", {"start": m["start"], "end": m["end"], "module_name": m["name"], "limit": 1})
    for _ in range(90):
        s = call("/api/job/" + j["job_id"])
        if s["done"]:
            break
        time.sleep(2)
    rec("analyze_module", json.dumps(s["result"], ensure_ascii=False)[:160])
    c = call("/api/comment?ea=%d&kind=func" % m["functions"][0]["ea"])
    rec("comment persisted", "%d chars" % len(c["comment"]))
    call("/api/close?save=false", {})
except Exception as e:
    import traceback; rec("ERROR", traceback.format_exc()[-600:])
print("\n".join(out))
sys.exit(1 if any(l.startswith("ERROR") for l in out) else 0)
