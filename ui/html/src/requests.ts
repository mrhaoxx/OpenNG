import './index.css'

type RequestInfo = Record<string, any>

function padZero(v: number): string { return v.toString().padStart(2, '0') }
function formatTime(ms: number): string {
  const seconds = Math.floor((ms / 1000) % 60)
  const minutes = Math.floor((ms / (1000 * 60)) % 60)
  const hours = Math.floor((ms / (1000 * 60 * 60)) % 24)
  return `${padZero(hours)}:${padZero(minutes)}:${padZero(seconds)}`
}

function showResult(message: string) {
  const resultText = document.getElementById('resultText')!
  resultText.textContent = message
  const dialog = document.getElementById('resultDialog') as HTMLDivElement
  dialog.classList.remove('hidden')
  dialog.classList.add('flex')
  document.getElementById('closeButton')!.addEventListener('click', () => {
    dialog.classList.add('hidden')
    dialog.classList.remove('flex')
  }, { once: true })
}

async function killRequest(requestId: string) {
  try {
    const resp = await fetch('/api/v1/http/request/kill', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `rid=${encodeURIComponent(requestId)}`
    })
    if (resp.ok) {
      showResult('Request killed successfully')
      void fetchRequests()
    } else {
      showResult('Failed to kill request')
    }
  } catch (e) {
    console.log(e)
  }
}

async function fetchRequests() {
  try {
    const resp = await fetch('/api/v1/http/requests')
    const data = await resp.json() as Record<string, RequestInfo>
    const requestList = document.getElementById('request-list') as HTMLUListElement
    requestList.innerHTML = ''

    for (const requestId in data) {
      const request = data[requestId]
      const li = document.createElement('li')
      li.className = 'py-3'

      const h3 = document.createElement('div')
      h3.className = 'text-sm font-medium text-neutral-900 dark:text-neutral-100'
      h3.textContent = `Request ID: ${requestId}`
      li.appendChild(h3)

      const meta = document.createElement('div')
      meta.className = 'mt-2 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-x-6 gap-y-1 text-xs text-neutral-700 dark:text-neutral-300 font-mono'
      for (const key in request) {
        if (key === 'starttime') {
          const startTime = new Date(request[key])
          const currentTime = new Date()
          const timeDiff = currentTime.getTime() - startTime.getTime()
          const div = document.createElement('div')
          div.textContent = `Elapsed: ${formatTime(timeDiff)}`
          meta.appendChild(div)
        } else {
          const div = document.createElement('div')
          div.textContent = `${key}: ${request[key]}`
          meta.appendChild(div)
        }
      }
      li.appendChild(meta)

      const actions = document.createElement('div')
      actions.className = 'mt-2'
      const killBtn = document.createElement('button')
      killBtn.className = 'px-3 py-1.5 rounded-md bg-red-600 text-white hover:bg-red-700'
      killBtn.textContent = 'Kill Request'
      killBtn.addEventListener('click', () => killRequest(requestId))
      actions.appendChild(killBtn)
      li.appendChild(actions)

      requestList.appendChild(li)
    }
  } catch (e) {
    console.log(e)
  }
}

async function updateUptime() {
  try {
    const resp = await fetch('/api/v1/uptime', { redirect: 'error' })
    if (!resp.ok) throw new Error('bad')
    const text = await resp.text()
    const el = document.getElementById('uptime')
    if (el) { el.textContent = text; el.classList.remove('disconnected') }
  } catch {
    const el = document.getElementById('uptime')
    if (el) { el.textContent = 'Disconnected'; el.classList.add('disconnected') }
  }
}

fetchRequests()
setInterval(fetchRequests, 1000)
updateUptime()
setInterval(updateUptime, 1000)


