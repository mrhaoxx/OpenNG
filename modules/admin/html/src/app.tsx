import { useState, useEffect, useCallback } from 'react'
import { LayoutGrid, Settings, ScrollText, Info } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import type { SpaceMapData } from '@/lib/api'
import { fetchJSON } from '@/lib/api'
import SpaceMap from '@/pages/SpaceMap'
import Instance from '@/pages/Instance'
import Config from '@/pages/Config'
import Logs from '@/pages/Logs'
import System from '@/pages/System'

type Route =
  | { page: 'map' }
  | { page: 'instance'; name: string }
  | { page: 'config' }
  | { page: 'logs' }
  | { page: 'sys' }

function parseHash(): Route {
  const hash = location.hash.slice(1) || '/'
  if (hash.startsWith('/instance/')) return { page: 'instance', name: hash.slice('/instance/'.length) }
  if (hash === '/config') return { page: 'config' }
  if (hash === '/logs') return { page: 'logs' }
  if (hash === '/sys') return { page: 'sys' }
  return { page: 'map' }
}

const railItems = [
  { id: 'map' as const, icon: LayoutGrid, label: 'Space Map', hash: '#/' },
  { id: 'config' as const, icon: Settings, label: 'Config', hash: '#/config' },
  { id: 'logs' as const, icon: ScrollText, label: 'Logs', hash: '#/logs' },
  { id: 'sys' as const, icon: Info, label: 'System', hash: '#/sys' },
]

export default function App() {
  const [route, setRoute] = useState<Route>(parseHash)
  const [spaceMap, setSpaceMap] = useState<SpaceMapData | null>(null)

  useEffect(() => {
    const onHash = () => setRoute(parseHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    fetchJSON<SpaceMapData>('/api/v1/space/map').then(setSpaceMap).catch(() => {})
  }, [])

  const nav = useCallback((hash: string) => { location.hash = hash }, [])
  const activeRail = route.page === 'instance' ? 'map' : route.page

  // Group all instances by kind prefix
  const instanceGroups: Record<string, { name: string; kind: string; hasAdmin: boolean }[]> = {}
  if (spaceMap) {
    for (const n of spaceMap.nodes) {
      const prefix = n.kind.split('::')[0] || 'other'
      ;(instanceGroups[prefix] ??= []).push(n)
    }
  }

  return (
    <div className="h-screen flex overflow-hidden bg-background text-foreground">
      {/* Icon Rail */}
      <div className="w-12 shrink-0 bg-neutral-950 flex flex-col items-center py-3 gap-1">
        <div className="w-8 h-8 rounded-lg bg-neutral-800 flex items-center justify-center text-xs font-bold text-white mb-3">
          NG
        </div>
        {railItems.map(item => (
          <button
            key={item.id}
            onClick={() => nav(item.hash)}
            title={item.label}
            className={`w-9 h-9 rounded-lg flex items-center justify-center transition-colors ${
              activeRail === item.id
                ? 'bg-primary text-primary-foreground'
                : 'text-neutral-500 hover:text-neutral-200 hover:bg-neutral-800'
            }`}
          >
            <item.icon size={18} />
          </button>
        ))}
      </div>

      {/* Panel */}
      <div className="w-52 shrink-0 bg-neutral-900 border-r border-neutral-800 flex flex-col">
        <div className="p-3 text-xs font-medium text-neutral-500 uppercase tracking-wider">
          {route.page === 'map' || route.page === 'instance' ? 'Instances' : railItems.find(r => r.id === route.page)?.label ?? ''}
        </div>
        <Separator className="bg-neutral-800" />
        <ScrollArea className="flex-1">
          <div className="p-2">
            {(route.page === 'map' || route.page === 'instance') && (
              <>
                {/* Space Map entry */}
                <button
                  onClick={() => nav('#/')}
                  className={`w-full text-left px-2 py-1.5 rounded-md text-sm transition-colors mb-2 ${
                    route.page === 'map' ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/50'
                  }`}
                >
                  <span className="block truncate">Space Map</span>
                  <span className="block text-[10px] text-neutral-600 truncate">overview</span>
                </button>

                {/* All instances grouped by kind prefix */}
                {Object.entries(instanceGroups).map(([prefix, nodes]) => (
                  <div key={prefix} className="mb-3">
                    <div className="text-[10px] font-medium text-neutral-600 uppercase tracking-wider px-2 mb-1">{prefix}</div>
                    {nodes.map(n => {
                      const active = route.page === 'instance' && route.name === n.name
                      return (
                        <button
                          key={n.name}
                          onClick={() => nav(`#/instance/${n.name}`)}
                          className={`w-full text-left px-2 py-1.5 rounded-md text-sm transition-colors ${
                            active ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/50'
                          }`}
                        >
                          <span className="block truncate font-mono">{n.name}</span>
                          <span className="block text-[10px] text-neutral-600 truncate">{n.kind}</span>
                        </button>
                      )
                    })}
                  </div>
                ))}
              </>
            )}
          </div>
        </ScrollArea>
        <div className="p-2 border-t border-neutral-800">
          <Badge variant="outline" className="text-[10px] border-neutral-700 text-neutral-500">
            {spaceMap?.nodes.length ?? '–'} services
          </Badge>
        </div>
      </div>

      {/* Content */}
      <main className="flex-1 overflow-auto">
        {route.page === 'map' && (spaceMap
          ? <SpaceMap data={spaceMap} onSelectNode={name => nav(`#/instance/${name}`)} />
          : <div className="flex items-center justify-center h-full text-muted-foreground">Loading...</div>
        )}
        {route.page === 'instance' && <Instance name={route.name} />}
        {route.page === 'config' && <Config />}
        {route.page === 'logs' && <Logs />}
        {route.page === 'sys' && <System />}
      </main>
    </div>
  )
}
