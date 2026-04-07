import { useState, useEffect, useCallback } from 'react'
import { LayoutGrid, Settings, ScrollText, Info } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import type { SpaceMapData, ModuleInfo } from '@/lib/api'
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
  const [modules, setModules] = useState<ModuleInfo[]>([])

  useEffect(() => {
    const onHash = () => setRoute(parseHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    fetchJSON<SpaceMapData>('/api/v1/space/map').then(setSpaceMap).catch(() => {})
    fetchJSON<ModuleInfo[]>('/api/v1/admin/modules').then(setModules).catch(() => {})
  }, [])

  const nav = useCallback((hash: string) => { location.hash = hash }, [])
  const activeRail = route.page === 'instance' ? 'map' : route.page

  // Group modules by category
  const categories: Record<string, ModuleInfo[]> = {}
  for (const m of modules) {
    const cat = m.meta?.category || 'Other'
    ;(categories[cat] ??= []).push(m)
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
                {Object.entries(categories).map(([cat, mods]) => (
                  <div key={cat} className="mb-3">
                    <div className="text-[10px] font-medium text-neutral-600 uppercase tracking-wider px-2 mb-1">{cat}</div>
                    {mods.map(m => {
                      const active = route.page === 'instance' && route.name === m.name
                      return (
                        <button
                          key={m.name}
                          onClick={() => nav(`#/instance/${m.name}`)}
                          className={`w-full text-left px-2 py-1.5 rounded-md text-sm transition-colors ${
                            active ? 'bg-neutral-800 text-neutral-100' : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/50'
                          }`}
                        >
                          <span className="block truncate">{m.meta?.title || m.name}</span>
                          <span className="block text-[10px] text-neutral-600 truncate">{m.kind}</span>
                        </button>
                      )
                    })}
                  </div>
                ))}
                {/* Non-admin instances */}
                {spaceMap && (() => {
                  const adminSet = new Set(modules.map(m => m.name))
                  const others = spaceMap.nodes.filter(n => !adminSet.has(n.name))
                  if (!others.length) return null
                  return (
                    <div className="mb-3">
                      <div className="text-[10px] font-medium text-neutral-600 uppercase tracking-wider px-2 mb-1">Other</div>
                      {others.map(n => (
                        <button
                          key={n.name}
                          onClick={() => nav(`#/instance/${n.name}`)}
                          className={`w-full text-left px-2 py-1.5 rounded-md text-sm text-neutral-500 hover:text-neutral-300 hover:bg-neutral-800/50 ${
                            route.page === 'instance' && route.name === n.name ? 'bg-neutral-800 text-neutral-100' : ''
                          }`}
                        >
                          <span className="block truncate">{n.name}</span>
                          <span className="block text-[10px] text-neutral-600 truncate">{n.kind}</span>
                        </button>
                      ))}
                    </div>
                  )
                })()}
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
