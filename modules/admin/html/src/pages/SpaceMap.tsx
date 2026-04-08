import { useRef, useState, useCallback, useEffect, useMemo } from 'react'
import type { SpaceMapData, SpaceNode } from '@/lib/api'
import ELK from 'elkjs/lib/elk.bundled'

const NODE_W = 140
const NODE_H = 44

interface LayoutNode extends SpaceNode {
  x: number
  y: number
}

interface LayoutEdge {
  from: string
  to: string
  sections?: { startPoint: { x: number; y: number }; endPoint: { x: number; y: number }; bendPoints?: { x: number; y: number }[] }[]
}

const elk = new ELK()

async function computeLayout(
  nodes: SpaceNode[],
  edges: { from: string; to: string }[]
): Promise<{ nodes: LayoutNode[]; edges: LayoutEdge[] }> {
  if (nodes.length === 0) return { nodes: [], edges: [] }

  // Filter edges: both endpoints must exist in nodes
  const nodeNames = new Set(nodes.map(n => n.name))
  const validEdges = edges.filter(e => nodeNames.has(e.from) && nodeNames.has(e.to))

  const connected = new Set<string>()
  for (const e of validEdges) { connected.add(e.from); connected.add(e.to) }

  const mainNodes = nodes.filter(n => connected.has(n.name))
  const isolated = nodes.filter(n => !connected.has(n.name))

  const graph = {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'DOWN',
      'elk.spacing.nodeNode': '40',
      'elk.layered.spacing.nodeNodeBetweenLayers': '80',
      'elk.edgeRouting': 'SPLINES',
      'elk.layered.crossingMinimization.strategy': 'LAYER_SWEEP',
      'elk.layered.nodePlacement.strategy': 'BRANDES_KOEPF',
    },
    children: mainNodes.map(n => ({
      id: n.name,
      width: NODE_W,
      height: NODE_H,
    })),
    edges: validEdges
      .map((e, i) => ({
        id: `e${i}`,
        sources: [e.from],
        targets: [e.to],
      })),
  }

  const layout = await elk.layout(graph)

  const resultNodes: LayoutNode[] = []
  const nodeMap = new Map(nodes.map(n => [n.name, n]))

  // Main graph nodes (ELK gives top-left coordinates, convert to center)
  for (const child of layout.children || []) {
    const n = nodeMap.get(child.id)
    if (n) {
      resultNodes.push({
        ...n,
        x: (child.x ?? 0) + NODE_W / 2,
        y: (child.y ?? 0) + NODE_H / 2,
      })
    }
  }

  // Isolated nodes: column to the right
  if (isolated.length > 0) {
    const maxX = resultNodes.length > 0
      ? Math.max(...resultNodes.map(n => n.x)) + NODE_W / 2
      : 0
    const isoX = maxX + NODE_W * 1.5
    for (let i = 0; i < isolated.length; i++) {
      resultNodes.push({
        ...isolated[i],
        x: isoX,
        y: i * (NODE_H + 20),
      })
    }
  }

  // Edges with routing info
  const resultEdges: LayoutEdge[] = (layout.edges || []).map(le => {
    const e = le as unknown as { sources: string[]; targets: string[]; sections?: LayoutEdge['sections'] }
    return { from: e.sources[0], to: e.targets[0], sections: e.sections }
  })

  return { nodes: resultNodes, edges: resultEdges }
}

function edgePath(edge: LayoutEdge, nodeMap: Map<string, LayoutNode>): string | null {
  // Use ELK's routed sections if available
  if (edge.sections?.length) {
    const parts: string[] = []
    for (const sec of edge.sections) {
      parts.push(`M${sec.startPoint.x},${sec.startPoint.y}`)
      if (sec.bendPoints?.length) {
        for (const bp of sec.bendPoints) {
          parts.push(`L${bp.x},${bp.y}`)
        }
      }
      parts.push(`L${sec.endPoint.x},${sec.endPoint.y}`)
    }
    return parts.join(' ')
  }

  // Fallback: simple curve
  const a = nodeMap.get(edge.from), b = nodeMap.get(edge.to)
  if (!a || !b) return null
  const x1 = a.x, y1 = a.y + NODE_H / 2
  const x2 = b.x, y2 = b.y - NODE_H / 2 - 8
  const midY = (y1 + y2) / 2
  return `M${x1},${y1} C${x1},${midY} ${x2},${midY} ${x2},${y2}`
}

export default function SpaceMap({ data, onSelectNode }: { data: SpaceMapData; onSelectNode: (name: string) => void }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [layoutResult, setLayoutResult] = useState<{ nodes: LayoutNode[]; edges: LayoutEdge[] } | null>(null)
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 })
  const panRef = useRef<{ sx: number; sy: number; tx: number; ty: number } | null>(null)

  useEffect(() => {
    computeLayout(data.nodes, data.edges).then(setLayoutResult)
  }, [data])

  // Fit to view
  useEffect(() => {
    const el = containerRef.current
    if (!el || !layoutResult?.nodes.length) return
    const ns = layoutResult.nodes
    const minX = Math.min(...ns.map(n => n.x)) - NODE_W
    const maxX = Math.max(...ns.map(n => n.x)) + NODE_W
    const minY = Math.min(...ns.map(n => n.y)) - NODE_H
    const maxY = Math.max(...ns.map(n => n.y)) + NODE_H * 2
    const cw = el.clientWidth, ch = el.clientHeight
    const scale = Math.min(1.3, cw / (maxX - minX) * 0.9, ch / (maxY - minY) * 0.9)
    setTransform({
      scale,
      x: (cw - (maxX - minX) * scale) / 2 - minX * scale,
      y: (ch - (maxY - minY) * scale) / 2 - minY * scale,
    })
  }, [layoutResult])

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    const rect = containerRef.current!.getBoundingClientRect()
    const mx = e.clientX - rect.left, my = e.clientY - rect.top
    const f = e.deltaY < 0 ? 1.1 : 1 / 1.1
    setTransform(t => {
      const s = Math.max(0.15, Math.min(4, t.scale * f))
      return { scale: s, x: mx - (mx - t.x) * (s / t.scale), y: my - (my - t.y) * (s / t.scale) }
    })
  }, [])

  const transformRef = useRef(transform)
  useEffect(() => { transformRef.current = transform }, [transform])

  const onBgDown = useCallback((e: React.MouseEvent) => {
    if ((e.target as Element).closest('[data-node]')) return
    const t = transformRef.current
    panRef.current = { sx: e.clientX, sy: e.clientY, tx: t.x, ty: t.y }
  }, [])

  useEffect(() => {
    function onMove(e: MouseEvent) {
      if (!panRef.current) return
      setTransform(t => ({
        ...t,
        x: panRef.current!.tx + e.clientX - panRef.current!.sx,
        y: panRef.current!.ty + e.clientY - panRef.current!.sy,
      }))
    }
    function onUp() { panRef.current = null }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
    return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', onUp) }
  }, [])

  if (!layoutResult) {
    return <div className="flex items-center justify-center h-full text-muted-foreground">Computing layout...</div>
  }

  const nodeMap = useMemo(() => new Map(layoutResult.nodes.map(n => [n.name, n])), [layoutResult])

  return (
    <div ref={containerRef}
      className="h-full w-full overflow-hidden cursor-grab active:cursor-grabbing bg-background"
      onWheel={onWheel} onMouseDown={onBgDown}>
      <svg className="w-full h-full select-none">
        <defs>
          <marker id="arr" markerWidth="10" markerHeight="10" refX="9" refY="4" orient="auto">
            <path d="M0,0 L0,8 L10,4 z" className="fill-muted-foreground/40" />
          </marker>
        </defs>
        <g transform={`translate(${transform.x},${transform.y}) scale(${transform.scale})`}>
          {/* Edges */}
          {layoutResult.edges.map((e, i) => {
            const d = edgePath(e, nodeMap)
            if (!d) return null
            return <path key={i} d={d}
              fill="none" className="stroke-muted-foreground/20" strokeWidth={1.2}
              markerEnd="url(#arr)" />
          })}

          {/* Nodes */}
          {layoutResult.nodes.map(n => (
            <g key={n.name} data-node transform={`translate(${n.x},${n.y})`}
              onClick={() => onSelectNode(n.name)} className="cursor-pointer">
              <rect x={-NODE_W / 2} y={-NODE_H / 2} width={NODE_W} height={NODE_H} rx={8}
                className={n.hasAdmin ? 'fill-card stroke-primary/30' : 'fill-card stroke-border'}
                strokeWidth={1.2} />
              {n.hasAdmin && <circle cx={NODE_W / 2 - 10} cy={-NODE_H / 2 + 10} r={2.5} className="fill-primary/60" />}
              <text textAnchor="middle" y={-4} fontSize={11} fontWeight={600}
                className="fill-foreground pointer-events-none" style={{ fontFamily: 'var(--font-sans)' }}>
                {n.name.length > 16 ? n.name.slice(0, 14) + '…' : n.name}
              </text>
              <text textAnchor="middle" y={12} fontSize={9}
                className="fill-muted-foreground pointer-events-none" style={{ fontFamily: 'var(--font-sans)' }}>
                {n.kind}
              </text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  )
}
