import { render } from 'preact'
import { useState, useEffect } from 'preact/hooks'
import './index.css'
import { SpaceMap } from './pages/space-map'
import { Instance } from './pages/instance'
import { Config } from './pages/config'
import { Logs } from './pages/logs'
import { Call } from './pages/call'
import { Sys } from './pages/sys'

type Route = { page: string; param?: string }

function parseHash(): Route {
  const hash = location.hash.slice(1) || '/'
  if (hash.startsWith('/instance/')) return { page: 'instance', param: hash.slice('/instance/'.length) }
  const page = hash.slice(1) || 'map'
  return { page }
}

function App() {
  const [route, setRoute] = useState<Route>(parseHash())
  const [modules, setModules] = useState<any[]>([])
  const [spaceMap, setSpaceMap] = useState<any>(null)

  useEffect(() => {
    const onHash = () => setRoute(parseHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    fetch('/api/v1/admin/modules').then(r => r.json()).then(setModules).catch(() => {})
    fetch('/api/v1/space/map').then(r => r.json()).then(setSpaceMap).catch(() => {})
  }, [])

  // Group modules by category
  const categories: Record<string, any[]> = {}
  for (const m of modules) {
    const cat = m.meta?.category || 'Other'
    ;(categories[cat] ??= []).push(m)
  }

  return (
    <div class="min-h-screen h-screen flex bg-white dark:bg-neutral-900 overflow-hidden">
      {/* Sidebar */}
      <nav class="w-56 border-r border-neutral-200 dark:border-neutral-800 bg-neutral-50 dark:bg-neutral-950 flex flex-col p-3 gap-1 overflow-y-auto shrink-0">
        <div class="text-lg font-semibold px-2 py-2 text-neutral-800 dark:text-neutral-100">NetGATE</div>

        <NavItem href="#/" label="Space Map" active={route.page === 'map'} />

        {Object.entries(categories).map(([cat, mods]) => (
          <div key={cat}>
            <div class="text-xs font-medium text-neutral-400 uppercase tracking-wider px-2 pt-3 pb-1">{cat}</div>
            {mods.map((m: any) => (
              <NavItem
                key={m.name}
                href={`#/instance/${m.name}`}
                label={m.meta?.title || m.name}
                sublabel={m.kind}
                active={route.page === 'instance' && route.param === m.name}
              />
            ))}
          </div>
        ))}

        <div class="text-xs font-medium text-neutral-400 uppercase tracking-wider px-2 pt-3 pb-1">System</div>
        <NavItem href="#/config" label="Config" active={route.page === 'config'} />
        <NavItem href="#/logs" label="Logs" active={route.page === 'logs'} />
        <NavItem href="#/call" label="Call" active={route.page === 'call'} />
        <NavItem href="#/sys" label="System" active={route.page === 'sys'} />
      </nav>

      {/* Content */}
      <main class="flex-1 overflow-hidden flex flex-col">
        {route.page === 'map' && <SpaceMap data={spaceMap} />}
        {route.page === 'instance' && route.param && <Instance name={route.param} />}
        {route.page === 'config' && <Config />}
        {route.page === 'logs' && <Logs />}
        {route.page === 'call' && <Call />}
        {route.page === 'sys' && <Sys />}
      </main>
    </div>
  )
}

interface NavItemProps {
  href: string
  label: string
  sublabel?: string
  active: boolean
}

function NavItem({ href, label, sublabel, active }: NavItemProps) {
  return (
    <a
      href={href}
      class={`block px-2 py-1.5 rounded text-sm ${active ? 'bg-sky-500 text-white' : 'text-neutral-700 dark:text-neutral-300 hover:bg-neutral-200 dark:hover:bg-neutral-800'}`}
    >
      {label}
      {sublabel && <span class="block text-xs opacity-60">{sublabel}</span>}
    </a>
  )
}

render(<App />, document.getElementById('app')!)
