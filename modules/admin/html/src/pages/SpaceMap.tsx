import { useRef, useEffect } from 'react'
import type { SpaceMapData } from '@/lib/api'
import { Network, type Options } from 'vis-network'
import { DataSet } from 'vis-data'

function truncate(s: string, max: number) {
  return s.length > max ? s.slice(0, max - 1) + '…' : s
}

export default function SpaceMap({ data, onSelectNode }: { data: SpaceMapData; onSelectNode: (name: string) => void }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const networkRef = useRef<Network | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    // Separate connected vs isolated nodes
    const connected = new Set<string>()
    const validEdges = data.edges.filter(e =>
      data.nodes.some(n => n.name === e.from) && data.nodes.some(n => n.name === e.to)
    )
    for (const e of validEdges) { connected.add(e.from); connected.add(e.to) }

    const connectedNodes = data.nodes.filter(n => connected.has(n.name))
    const isolatedNodes = data.nodes.filter(n => !connected.has(n.name))

    const nodes = new DataSet(
      data.nodes.map(n => ({
        id: n.name,
        label: `${truncate(n.name, 16)}\n${truncate(n.kind || '(no kind)', 20)}`,
        ...(connected.has(n.name) ? {} : { group: 'isolated' }),
        ...(n.hasAdmin ? { group: 'admin' } : {}),
      }))
    )

    const edges = new DataSet(
      validEdges.map((e, i) => ({ id: `e${i}`, from: e.from, to: e.to }))
    )

    const options: Options = {
      layout: {
        hierarchical: {
          enabled: true,
          direction: 'UD',
          sortMethod: 'directed',
          shakeTowards: 'roots',
          nodeSpacing: 180,
          levelSeparation: 80,
          treeSpacing: 100,
          blockShifting: true,
          edgeMinimization: true,
          parentCentralization: true,
        },
      },
      physics: { enabled: false },
      interaction: {
        hover: true,
        tooltipDelay: 100,
        zoomView: true,
        dragView: true,
        dragNodes: false,
      },
      edges: {
        arrows: { to: { enabled: true, scaleFactor: 0.4, type: 'arrow' } },
        color: { color: 'rgba(255,255,255,0.1)', hover: 'rgba(255,255,255,0.25)', highlight: 'rgba(100,180,255,0.4)' },
        smooth: { enabled: true, type: 'cubicBezier', forceDirection: 'vertical', roundness: 0.4 },
        width: 1,
        hoverWidth: 0.3,
      },
      nodes: {
        shape: 'box',
        widthConstraint: { minimum: 90, maximum: 150 },
        margin: { top: 5, bottom: 5, left: 8, right: 8 },
        font: {
          face: 'ui-monospace, SFMono-Regular, Menlo, monospace',
          size: 11,
          color: '#d4d4d4',
          multi: false,
          align: 'center',
        },
        color: {
          background: '#1a1a1a',
          border: '#333',
          hover: { background: '#222', border: '#555' },
          highlight: { background: '#1e3a5f', border: '#3b82f6' },
        },
        borderWidth: 1,
        borderWidthSelected: 1.5,
        shapeProperties: { borderRadius: 5 },
      },
      groups: {
        admin: {
          color: { border: 'rgba(59,130,246,0.5)' },
          borderWidth: 1.5,
        },
        isolated: {
          color: { background: '#151515', border: '#2a2a2a' },
          font: { color: '#777' },
        },
      },
    }

    const network = new Network(containerRef.current, { nodes, edges }, options)
    networkRef.current = network

    network.on('click', (params) => {
      if (params.nodes.length > 0) {
        onSelectNode(params.nodes[0] as string)
      }
    })

    // After initial draw: reflow wide layers + move isolated nodes
    network.once('afterDrawing', () => {
      const positions = network.getPositions()
      const maxPerRow = 4
      const nodeW = 160
      const nodeH = 50
      const hGap = 20
      const vGap = 16

      // Group connected nodes by Y level
      const layers = new Map<number, { id: string; x: number; y: number }[]>()
      for (const n of connectedNodes) {
        const pos = positions[n.name]
        if (!pos) continue
        // Round Y to group into layers (vis-network uses exact same Y for same level)
        const ly = Math.round(pos.y)
        if (!layers.has(ly)) layers.set(ly, [])
        layers.get(ly)!.push({ id: n.name, x: pos.x, y: pos.y })
      }

      // Reflow layers that are too wide
      let yShift = 0
      const sortedLayers = [...layers.entries()].sort((a, b) => a[0] - b[0])
      for (const [, layerNodes] of sortedLayers) {
        // Apply accumulated shift from previous reflows
        for (const n of layerNodes) n.y += yShift

        if (layerNodes.length > maxPerRow) {
          layerNodes.sort((a, b) => a.x - b.x)
          const rows = Math.ceil(layerNodes.length / maxPerRow)
          const baseY = layerNodes[0].y
          // Center each row
          const medianX = layerNodes[Math.floor(layerNodes.length / 2)].x
          for (let i = 0; i < layerNodes.length; i++) {
            const row = Math.floor(i / maxPerRow)
            const col = i % maxPerRow
            const rowCount = Math.min(maxPerRow, layerNodes.length - row * maxPerRow)
            const rowW = rowCount * (nodeW + hGap) - hGap
            const rowStartX = medianX - rowW / 2 + nodeW / 2
            layerNodes[i].x = rowStartX + col * (nodeW + hGap)
            layerNodes[i].y = baseY + row * (nodeH + vGap)
          }
          yShift += (rows - 1) * (nodeH + vGap)
        }

        // Apply final positions
        for (const n of layerNodes) {
          network.moveNode(n.id, n.x, n.y)
        }
      }

      // Move isolated nodes to a row below the main graph
      if (isolatedNodes.length > 0) {
        let maxY = -Infinity
        let sumX = 0
        let countX = 0
        for (const n of connectedNodes) {
          const pos = positions[n.name]
          if (pos) {
            if (pos.y + yShift > maxY) maxY = pos.y + yShift
            sumX += pos.x
            countX++
          }
        }
        const centerX = countX > 0 ? sumX / countX : 0
        const isoY = maxY + nodeH + 40
        const totalW = isolatedNodes.length * (nodeW + hGap) - hGap
        const startX = centerX - totalW / 2 + nodeW / 2
        isolatedNodes.forEach((n, i) => {
          network.moveNode(n.name, startX + i * (nodeW + hGap), isoY)
        })
      }

      network.fit({ animation: false })
    })

    return () => {
      network.destroy()
      networkRef.current = null
    }
  }, [data, onSelectNode])

  return (
    <div ref={containerRef} className="h-full w-full bg-background" />
  )
}
