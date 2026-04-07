import { useEffect, useRef, useState } from 'react'
import type { SpaceMapData, SpaceNode } from '@/lib/api'

interface SimNode extends SpaceNode { x: number; y: number; vx: number; vy: number }

const W = 140, H = 40

export default function SpaceMap({ data, onSelectNode }: { data: SpaceMapData; onSelectNode: (name: string) => void }) {
  const svgRef = useRef<SVGSVGElement>(null)
  const nodesRef = useRef<SimNode[]>([])
  const [, tick] = useState(0)
  const animRef = useRef(0)

  useEffect(() => {
    nodesRef.current = data.nodes.map((n, i) => ({
      ...n,
      x: 400 + 180 * Math.cos(2 * Math.PI * i / data.nodes.length),
      y: 300 + 180 * Math.sin(2 * Math.PI * i / data.nodes.length),
      vx: 0, vy: 0,
    }))
  }, [data.nodes])

  useEffect(() => {
    let running = true
    const byName = new Map<string, SimNode>()

    function step() {
      if (!running) return
      const nodes = nodesRef.current
      byName.clear()
      nodes.forEach(n => byName.set(n.name, n))

      // repulsion
      for (let i = 0; i < nodes.length; i++)
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y
          const d2 = dx * dx + dy * dy + 1, d = Math.sqrt(d2), f = 6000 / d2
          const fx = (dx / d) * f, fy = (dy / d) * f
          nodes[i].vx -= fx; nodes[i].vy -= fy
          nodes[j].vx += fx; nodes[j].vy += fy
        }
      // springs
      for (const e of data.edges) {
        const a = byName.get(e.from), b = byName.get(e.to)
        if (!a || !b) continue
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) + .001
        const f = (d - 180) * 0.04
        a.vx += (dx / d) * f; a.vy += (dy / d) * f
        b.vx -= (dx / d) * f; b.vy -= (dy / d) * f
      }
      // center + damp
      for (const n of nodes) {
        n.vx += (400 - n.x) * 0.008; n.vy += (300 - n.y) * 0.008
        n.vx *= 0.88; n.vy *= 0.88
        n.x += n.vx; n.y += n.vy
      }
      tick(k => k + 1)
      const maxV = nodes.reduce((m, n) => Math.max(m, Math.abs(n.vx), Math.abs(n.vy)), 0)
      if (maxV > 0.15) animRef.current = requestAnimationFrame(step)
    }
    animRef.current = requestAnimationFrame(step)
    return () => { running = false; cancelAnimationFrame(animRef.current) }
  }, [data])

  const nodes = nodesRef.current
  const byName = new Map(nodes.map(n => [n.name, n]))

  return (
    <div className="h-full p-6">
      <h1 className="text-lg font-semibold mb-4">Space Map</h1>
      <div className="border border-border rounded-xl overflow-hidden bg-card">
        <svg ref={svgRef} viewBox="0 0 800 600" className="w-full" style={{ minHeight: 400 }}>
          <defs>
            <marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L0,6 L8,3 z" className="fill-muted-foreground" />
            </marker>
          </defs>
          {data.edges.map((e, i) => {
            const a = byName.get(e.from), b = byName.get(e.to)
            if (!a || !b) return null
            const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) + .001
            return <line key={i}
              x1={a.x + dx / d * W / 2} y1={a.y + dy / d * H / 2}
              x2={b.x - dx / d * (W / 2 + 8)} y2={b.y - dy / d * (H / 2 + 8)}
              className="stroke-muted-foreground/40" strokeWidth={1.5} markerEnd="url(#arr)" />
          })}
          {nodes.map(n => (
            <g key={n.name} transform={`translate(${n.x},${n.y})`}
              className="cursor-pointer" onClick={() => onSelectNode(n.name)}>
              <rect x={-W / 2} y={-H / 2} width={W} height={H} rx={8}
                className={n.hasAdmin ? 'fill-card stroke-primary/50' : 'fill-card stroke-border'}
                strokeWidth={1.5} />
              <text textAnchor="middle" y={-4} fontSize={11} fontWeight={600}
                className="fill-foreground" style={{ fontFamily: 'var(--font-sans)' }}>
                {n.name.length > 16 ? n.name.slice(0, 14) + '…' : n.name}
              </text>
              <text textAnchor="middle" y={12} fontSize={9}
                className="fill-muted-foreground" style={{ fontFamily: 'var(--font-sans)' }}>
                {n.kind}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  )
}
