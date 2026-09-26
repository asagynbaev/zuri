const usd = (units) =>
  '$' + (units / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })

const monthName = (period, month = 'long') =>
  period === 'all'
    ? 'All payments'
    : new Date(period + '-01T00:00:00Z').toLocaleString('en-US', { month, year: 'numeric', timeZone: 'UTC' })

const day = (unix) =>
  new Date(unix * 1000).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' })

const short = (s) => s.slice(0, 4) + '…' + s.slice(-4)

const explorer = (sig) => `https://explorer.solana.com/tx/${sig}?cluster=devnet`

// "3,000" or "$3000.5" -> "3000.5", which the server parses.
const amountInput = (s) => s.replace(/[$,\s]/g, '')

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) {
    if (k === 'style') el.style.cssText = v
    else if (k === 'class') el.className = v
    else el.setAttribute(k, v)
  }
  el.append(...children.flat().filter((c) => c != null))
  return el
}

function txLinks(sigs) {
  return sigs.map((sig) => h('a', { href: explorer(sig), target: '_blank', rel: 'noopener' }, short(sig) + ' ↗'))
}

async function api(path, body) {
  const init = body
    ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
    : {}
  const res = await fetch(path, init)
  const data = await res.json()
  if (!res.ok) throw new Error(data.error || res.statusText)
  return data
}

// Redaction bars get slightly different widths so they look like real text.
const barWidth = (i) => 70 + ((i * 37) % 40) + 'px'
