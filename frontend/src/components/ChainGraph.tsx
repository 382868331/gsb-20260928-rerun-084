import { useMemo } from "react";
import { ReactFlow, Background, Controls, MarkerType } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { Edge, Node } from "@xyflow/react";
import type { LabState } from "../types";

export function ChainGraph({ state, highlightPath }: { state: LabState; highlightPath?: string[] }) {
  const { nodes, edges } = useMemo(() => buildGraph(state, highlightPath), [state, highlightPath]);
  return (
    <div className="graph">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }} nodesDraggable nodesConnectable={false}>
        <Background color="#2b3656" gap={22} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}

function depthOf(certId: string, state: LabState, memo: Map<string, number>): number {
  if (memo.has(certId)) return memo.get(certId)!;
  const c = state.certs[certId];
  if (!c || !c.issuerId) {
    memo.set(certId, 0);
    return 0;
  }
  const d = depthOf(c.issuerId, state, memo) + 1;
  memo.set(certId, d);
  return d;
}

function buildGraph(state: LabState, highlight?: string[]): { nodes: Node[]; edges: Edge[] } {
  const depths = new Map<string, number>();
  const byDepth = new Map<number, string[]>();
  for (const id of Object.keys(state.certs)) {
    const d = depthOf(id, state, depths);
    byDepth.set(d, [...(byDepth.get(d) ?? []), id]);
  }

  const hi = new Set(highlight ?? []);
  const nodes: Node[] = [];
  for (const [d, ids] of byDepth) {
    ids.sort((a, b) => state.certs[a].subject.localeCompare(state.certs[b].subject) || state.certs[a].version - state.certs[b].version);
    ids.forEach((id, i) => {
      const c = state.certs[id];
      const kind = !c.issuerId ? "root" : c.isCA ? "intermediate" : "leaf";
      const color = kind === "root" ? "#ffb454" : kind === "intermediate" ? "#6ea8fe" : "#38d39f";
      const bad = c.revoked || new Date(c.notAfter).getTime() < Date.now();
      nodes.push({
        id,
        position: { x: d * 280, y: i * 92 },
        data: {
          label: `${c.subject} v${c.version}${c.crossSignedBy ? " ⤨交叉" : ""}${c.revoked ? " 撤销" : bad ? " 过期" : ""}`,
        },
        style: {
          background: hi.has(id) ? "rgba(56,211,159,.25)" : "#0f1420",
          border: `1px solid ${c.revoked || bad ? "#ff6b6b" : color}`,
          borderRadius: 8,
          color: "#e6ecf8",
          fontSize: 11,
          padding: 6,
          width: 190,
          borderStyle: c.crossSignedBy ? "dashed" : "solid",
        },
      });
    });
  }

  const edges: Edge[] = [];
  for (const c of Object.values(state.certs)) {
    if (!c.issuerId || !state.certs[c.issuerId]) continue;
    edges.push({
      id: `${c.id}-${c.issuerId}`,
      source: c.issuerId,
      target: c.id,
      animated: hi.has(c.id) && hi.has(c.issuerId),
      style: {
        stroke: c.crossSignedBy ? "#ffb454" : hi.has(c.id) ? "#38d39f" : "#5a6a92",
        strokeDasharray: c.crossSignedBy ? "6 4" : undefined,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: c.crossSignedBy ? "#ffb454" : "#5a6a92" },
    });
  }
  return { nodes, edges };
}
