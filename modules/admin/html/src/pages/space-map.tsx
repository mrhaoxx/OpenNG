import { useEffect, useRef, useState } from 'preact/hooks'

interface Node {
  name: string
  kind: string
  hasAdmin?: boolean
  x?: number
  y?: number
  vx?: number
  vy?: number
}

interface Edge {
  from: string
  to: string
}

interface SpaceMapData {
  nodes: Node[]
  edges: Edge[]
}

const KIND_COLORS: Record<string, string> = {
  auth: '#6366f1',
  proxy: '#22c55e',
  tls: '#f59e0b',
  tcp: '#3b82f6',
  http: '#ec4899',
  admin: '#8b5cf6',
  default: '#94a3b8',
}

function getKindColor(kind: string): string {
  const prefix = kind.split('.')[0]?.toLowerCase() || ''
  return KIND_COLORS[prefix] || KIND_COLORS['default']
}

interface SpaceMapProps {
  data: SpaceMapData | null
}

export function SpaceMap({ data }: SpaceMapProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const animFrameRef = useRef<number>(0)
  const [nodes, setNodes] = useState<Node[]>([])
  const [edges, setEdges] = useState<Edge[]>([])
  const [dims, setDims] = useState({ w: 800, h: 600 })
  const nodesRef = useRef<Node[]>([])

  useEffect(() => {
    if (!svgRef.current) return
    const obs = new ResizeObserver(entries => {
      const e = entries[0]
      if (e) setDims({ w: e.contentRect.width, h: e.contentRect.height })
    })
    obs.observe(svgRef.current)
    return () => obs.disconnect()
  }, [])

  useEffect(() => {
    if (!data?.nodes) return

    // Initialize positions
    const { w, h } = dims
    const initialized = data.nodes.map((n, i) => ({
      ...n,
      x: w / 2 + Math.cos((i / data.nodes.length) * 2 * Math.PI) * (Math.min(w, h) * 0.3),
      y: h / 2 + Math.sin((i / data.nodes.length) * 2 * Math.PI) * (Math.min(w, h) * 0.3),
      vx: 0,
      vy: 0,
    }))

    nodesRef.current = initialized
    setNodes([...initialized])
    setEdges(data.edges || [])
  }, [data, dims])

  // Force simulation
  useEffect(() => {
    if (nodes.length === 0) return
    const { w, h } = dims

    function tick() {
      const ns = nodesRef.current
      if (!ns.length) return

      const k = 0.03
      const repulsion = 3000
      const linkDist = 120
      const damping = 0.85

      // Build index
      const idx: Record<string, Node> = {}
      ns.forEach(n => { idx[n.name] = n })

      // Repulsion
      for (let i = 0; i < ns.length; i++) {
        for (let j = i + 1; j < ns.length; j++) {
          const a = ns[i], b = ns[j]
          const dx = (b.x || 0) - (a.x || 0)
          const dy = (b.y || 0) - (a.y || 0)
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          const force = repulsion / (dist * dist)
          const fx = (dx / dist) * force
          const fy = (dy / dist) * force
          a.vx! -= fx
          a.vy! -= fy
          b.vx! += fx
          b.vy! += fy
        }
      }

      // Attraction along edges
      for (const e of edges) {
        const a = idx[e.from], b = idx[e.to]
        if (!a || !b) continue
        const dx = (b.x || 0) - (a.x || 0)
        const dy = (b.y || 0) - (a.y || 0)
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const force = (dist - linkDist) * k
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        a.vx! += fx; a.vy! += fy
        b.vx! -= fx; b.vy! -= fy
      }

      // Center gravity
      for (const n of ns) {
        n.vx! += (w / 2 - (n.x || 0)) * 0.005
        n.vy! += (h / 2 - (n.y || 0)) * 0.005
        n.vx! *= damping
        n.vy! *= damping
        n.x! += n.vx!
        n.y! += n.vy!
        // Clamp
        n.x = Math.max(30, Math.min(w - 30, n.x || 0))
        n.y = Math.max(30, Math.min(h - 30, n.y || 0))
      }

      setNodes([...ns])
      animFrameRef.current = requestAnimationFrame(tick)
    }

    animFrameRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(animFrameRef.current)
  }, [nodes.length, edges, dims])

  // Build edge index for lookup
  const nodePos: Record<string, { x: number; y: number }> = {}
  nodes.forEach(n => { nodePos[n.name] = { x: n.x || 0, y: n.y || 0 } })

  if (!data) {
    return (
      <div class="flex items-center justify-center h-full text-neutral-400 text-sm">
        Loading space map...
      </div>
    )
  }

  return (
    <div class="flex flex-col h-full">
      <div class="px-6 py-4 border-b border-neutral-200 dark:border-neutral-800">
        <h1 class="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Space Map</h1>
        <p class="text-sm text-neutral-500 mt-0.5">{nodes.length} nodes, {edges.length} edges</p>
      </div>
      <div class="flex-1 min-h-0">
        <svg ref={svgRef} class="w-full h-full" style="min-height: 400px">
          <defs>
            <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L0,6 L8,3 z" fill="#94a3b8" />
            </marker>
          </defs>
          {/* Edges */}
          {edges.map((e, i) => {
            const from = nodePos[e.from]
            const to = nodePos[e.to]
            if (!from || !to) return null
            return (
              <line
                key={i}
                x1={from.x} y1={from.y}
                x2={to.x} y2={to.y}
                stroke="#cbd5e1"
                stroke-width="1.5"
                stroke-opacity="0.6"
                marker-end="url(#arrow)"
              />
            )
          })}
          {/* Nodes */}
          {nodes.map(n => {
            const color = getKindColor(n.kind)
            const hasAdmin = n.hasAdmin
            return (
              <g
                key={n.name}
                transform={`translate(${n.x || 0},${n.y || 0})`}
                class="cursor-pointer"
                onClick={() => hasAdmin && (location.hash = `#/instance/${n.name}`)}
                style={{ cursor: hasAdmin ? 'pointer' : 'default' }}
              >
                <circle
                  r={hasAdmin ? 20 : 14}
                  fill={color}
                  fill-opacity="0.85"
                  stroke={hasAdmin ? 'white' : 'none'}
                  stroke-width="2"
                />
                <text
                  text-anchor="middle"
                  y={hasAdmin ? 30 : 24}
                  font-size="10"
                  fill="#64748b"
                  class="select-none"
                >
                  {n.name.length > 12 ? n.name.slice(0, 11) + '…' : n.name}
                </text>
                <title>{n.name} ({n.kind})</title>
              </g>
            )
          })}
        </svg>
      </div>
    </div>
  )
}
