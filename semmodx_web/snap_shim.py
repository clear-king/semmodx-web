"""
Minimal pure-Python stand-in for the subset of SNAP (Stanford Network Analysis
Platform) that SemModX's codecut/ modules actually use.

Why this exists: the `snap` package installed in this conda env is NOT SNAP —
it is "snap 0.5, a zope 3 frontend for entransit", an empty stub with zero
attributes. The plugin needs the real thing (PyPI: snap-stanford). Rather than
force that install, this module implements just the API surface used by
semmodx/codecut/snap_cg.py and semmodx/codecut/maxcut.py:

    snap.TIntV().Add(x)
    snap.PNGraph.New()
    snap.ConvertGraph(snap.PNGraph, g)
    snap.GetSubGraph(g, node_ids)
    g.AddNode(id) / g.IsNode(id) / g.DelNode(id)
    g.AddEdge(src, dst)
    g.GetNodes() -> int
    g.Nodes() -> iterator of NodeI   (GetId / GetInDeg / GetOutDeg)
    g.GetNI(id) -> NodeI
    g.Edges() -> iterator of EdgeI   (GetSrcNId / GetDstNId)

Semantics match SNAP's TNGraph: nodes are ints, edges are directed, DelNode
removes incident edges, GetSubGraph keeps only edges with both endpoints inside.
"""


class TIntV(object):
    """SNAP integer vector."""
    def __init__(self):
        self._v = []

    def Add(self, x):
        self._v.append(x)

    def Len(self):
        return len(self._v)

    def __len__(self):
        return len(self._v)

    def __iter__(self):
        return iter(self._v)

    def __contains__(self, x):
        return x in self._v

    def __getitem__(self, i):
        return self._v[i]


class NodeI(object):
    """Read-only node handle. Degrees are looked up live on the parent graph."""
    __slots__ = ("_g", "_id")

    def __init__(self, g, nid):
        self._g = g
        self._id = nid

    def GetId(self):
        return self._id

    def GetInDeg(self):
        return len(self._g._in.get(self._id, ()))

    def GetOutDeg(self):
        return len(self._g._out.get(self._id, ()))

    def __repr__(self):
        return "NodeI(%d, in=%d, out=%d)" % (self._id, self.GetInDeg(), self.GetOutDeg())


class EdgeI(object):
    """Read-only edge handle."""
    __slots__ = ("_src", "_dst")

    def __init__(self, src, dst):
        self._src = src
        self._dst = dst

    def GetSrcNId(self):
        return self._src

    def GetDstNId(self):
        return self._dst

    def __repr__(self):
        return "EdgeI(%d -> %d)" % (self._src, self._dst)


class PNGraph(object):
    """Directed graph over integer node ids."""

    def __init__(self):
        self._nodes = set()          # ordered-by-insertion set emulation
        self._order = []
        self._out = {}               # id -> set of dst ids
        self._in = {}                # id -> set of src ids

    @staticmethod
    def New():
        return PNGraph()

    # --- mutation ---------------------------------------------------------
    def AddNode(self, nid):
        nid = int(nid)
        if nid not in self._nodes:
            self._nodes.add(nid)
            self._order.append(nid)
            self._out[nid] = set()
            self._in[nid] = set()
        return nid

    def AddEdge(self, src, dst):
        src, dst = int(src), int(dst)
        # SNAP auto-creates endpoints unless AddEdge is called in strict mode;
        # the plugin pre-adds nodes, but be forgiving like SNAP is.
        if src not in self._nodes:
            self.AddNode(src)
        if dst not in self._nodes:
            self.AddNode(dst)
        self._out[src].add(dst)
        self._in[dst].add(src)
        return -1

    def DelNode(self, nid):
        nid = int(nid)
        if nid not in self._nodes:
            return
        for d in self._out[nid]:
            self._in[d].discard(nid)
        for s in self._in[nid]:
            self._out[s].discard(nid)
        self._out.pop(nid, None)
        self._in.pop(nid, None)
        self._nodes.discard(nid)
        self._order.remove(nid)

    # --- queries ----------------------------------------------------------
    def IsNode(self, nid):
        return int(nid) in self._nodes

    def GetNodes(self):
        return len(self._nodes)

    def GetEdges(self):
        return sum(len(v) for v in self._out.values())

    def Nodes(self):
        # SNAP yields nodes in ascending id order for TNGraph; maxcut.py
        # early-breaks on `start > region_end`, so order matters.
        for nid in sorted(self._nodes):
            yield NodeI(self, nid)

    def GetNI(self, nid):
        nid = int(nid)
        if nid not in self._nodes:
            raise RuntimeError("node %d not in graph" % nid)
        return NodeI(self, nid)

    def Edges(self):
        for src in sorted(self._nodes):
            for dst in sorted(self._out[src]):
                yield EdgeI(src, dst)

    def __repr__(self):
        return "PNGraph(%d nodes, %d edges)" % (self.GetNodes(), self.GetEdges())


def ConvertGraph(target_type, graph):
    """Deep copy (only PNGraph -> PNGraph is needed here)."""
    if target_type is not PNGraph and getattr(target_type, "__name__", "") != "PNGraph":
        raise NotImplementedError("ConvertGraph only supports PNGraph targets")
    g = PNGraph()
    for nid in graph._order:
        g.AddNode(nid)
    for src in graph._order:
        for dst in graph._out[src]:
            g.AddEdge(src, dst)
    return g


def GetSubGraph(graph, node_ids):
    """Subgraph induced by node_ids; edges kept only when fully inside."""
    keep = set(int(x) for x in node_ids)
    g = PNGraph()
    for nid in graph._order:
        if nid in keep:
            g.AddNode(nid)
    for src in graph._order:
        if src not in keep:
            continue
        for dst in graph._out[src]:
            if dst in keep:
                g.AddEdge(src, dst)
    return g


def install():
    """Force-register this module as `snap` in sys.modules."""
    import sys
    sys.modules["snap"] = sys.modules[__name__]
    return sys.modules["snap"]
