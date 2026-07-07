/**
 * app.js
 * Renderer process UI logic.
 * Communicates with the main process only through window.rdm (exposed by preload.js).
 */

'use strict'

// ─── State ────────────────────────────────────────────────────────────────────
const State = {
  devices:      [],     // All discovered devices
  nodes:        [],     // Discovered Art-Net / sACN nodes
  filtered:     [],     // Devices after filter/sort
  scanning:     false,
  activeDevice: null,
  isDemo:       false,
  protocol:     'both', // 'artnet', 'sacn', or 'both'
  hidePassive:  false,  // hide passive ArtDmx sources (media servers / consoles)
  nodeFilter:   null,   // when set (node IP), device grid shows only that node's fixtures
}

// ─── Init ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
  // Dynamically load the version from package.json via main process
  // so the UI never shows a stale hardcoded version number.
  try {
    const ver = await window.rdm.getAppVersion()
    if (ver) document.getElementById('app-version').textContent = `v${ver}`
  } catch (_) {}

  await loadInterfaces()
  await loadManualNodes()

  window.rdm.onNodeFound(   (node)   => addNode(node))
  window.rdm.onDeviceFound( (device) => addDevice(device))
  window.rdm.onProgress(    (data)   => {
    const msg  = data.message || ''
    const type = data.done    ? 'done'
               : data.error   ? 'err'
               : msg.includes('WARNING') || msg.includes('⚠') ? 'warn'
               : ''
    log(msg, type)
  })
  window.rdm.onScanDone(    (data)   => scanFinished(data))
  window.rdm.onError(       (data)   => { log('Error: ' + data.message, 'err'); scanFinished(null, true) })
  window.rdm.onUpdateAvailable((info) => showUpdateBanner(info))
  window.rdm.onUpdateProgress((p)    => updateBannerProgress(p))
  window.rdm.onUpdateDownloaded((info)=> showUpdateReady(info))

  // ── Wire up UI event listeners ───────────────────────────────────────────
  document.getElementById('scanBtn').addEventListener('click', () => App.startScan())
  document.getElementById('addManualNodeBtn').addEventListener('click', () => App.addManualNode())
  document.getElementById('manualNodeIp').addEventListener('keydown', e => { if (e.key === 'Enter') App.addManualNode() })
  document.getElementById('demoBtn').addEventListener('click', () => App.loadDemo())
  document.getElementById('filterInput').addEventListener('input', () => App.applyFilter())
  document.getElementById('categoryFilter').addEventListener('change', () => App.applyFilter())
  document.getElementById('sortSelect').addEventListener('change', () => App.applyFilter())

  // Protocol toggle
  document.querySelectorAll('.proto-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.proto-btn').forEach(b => b.classList.remove('proto-active'))
      btn.classList.add('proto-active')
      State.protocol = btn.dataset.proto
    })
  })

  // Modal
  document.getElementById('modal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('modal')) App.closeModal()
  })
  document.querySelector('.modal').addEventListener('click', (e) => e.stopPropagation())
  document.getElementById('modalCloseBtn').addEventListener('click', () => App.closeModal())

  // Modal actions
  document.getElementById('applyAddressBtn').addEventListener('click', () => App.applyDmxAddress())
  document.getElementById('applyLabelBtn').addEventListener('click', () => App.applyDeviceLabel())
  document.getElementById('identifyOnBtn').addEventListener('click', () => App.identifyOn())
  document.getElementById('identifyOffBtn').addEventListener('click', () => App.identifyOff())
  document.getElementById('applyPersonalityBtn').addEventListener('click', () => App.applyPersonality())

  // Fixture cards are (re)rendered via innerHTML, which cannot carry element
  // listeners — a single delegated listener on the grid works for every card,
  // no matter how it was rendered.  (Per-card listeners silently died in
  // serialization since the grid was first written — clicking never worked.)
  document.getElementById('deviceGrid').addEventListener('click', (e) => {
    const card = e.target.closest('.device-card')
    if (card && card.dataset.uid) App.openModal(card.dataset.uid)
  })

  // Update banner
  document.getElementById('updateDismiss').addEventListener('click', () => {
    document.getElementById('updateBanner').style.display = 'none'
    document.body.classList.remove('has-update')
  })

  // Copy log to clipboard
  document.getElementById('copyLogBtn').addEventListener('click', () => App.copyLog())

  // Open logs folder in OS file manager
  document.getElementById('openLogsBtn').addEventListener('click', () => window.rdm.openLogsFolder())

  // Hide / show passive ArtDmx sources in the node list
  document.getElementById('hidePassiveBtn').addEventListener('click', () => App.toggleHidePassive())
})

// ─── Manual Nodes ─────────────────────────────────────────────────────────────
async function loadManualNodes() {
  const nodes = await window.rdm.getManualNodes()
  renderManualNodes(nodes)
  // Manual nodes are NOT added to the main Nodes panel here.
  // They appear there only after a scan — either with real info when found,
  // or with a "not found" indicator when the scan couldn't reach them.
}

function renderManualNodes(nodes) {
  const list = document.getElementById('manualNodeList')
  if (!nodes || nodes.length === 0) {
    list.innerHTML = '<li class="manual-node-empty">No manual nodes added</li>'
    return
  }
  list.innerHTML = nodes.map(n => `
    <li class="manual-node-item">
      <div class="manual-node-info">
        <span class="manual-node-name-text">${escHtml(n.name)}</span>
        <span class="manual-node-ip-text">${escHtml(n.ip)}</span>
      </div>
      <button class="manual-node-remove" onclick="App.removeManualNode('${escHtml(n.ip)}')" title="Remove">✕</button>
    </li>
  `).join('')
}

// ─── Network Interfaces ───────────────────────────────────────────────────────
async function loadInterfaces() {
  const ifaces = await window.rdm.getNetworkInterfaces()
  const sel = document.getElementById('ifaceSelect')
  sel.innerHTML = ifaces.map(i =>
    `<option value="${i.address}" data-broadcast="${i.broadcast || '255.255.255.255'}">${i.label}</option>`
  ).join('')
}

// ─── Update Banner ──────────────────────────────────────────────────────────
function showUpdateBanner(info) {
  const link = document.getElementById('updateLink')
  if (info.downloading) {
    // Packaged build: electron-updater is fetching it in the background
    document.getElementById('updateText').textContent = `Downloading RDM Explorer v${info.version}…`
    link.style.display = 'none'
  } else {
    // Dev / fallback: link out to the releases page
    document.getElementById('updateText').textContent = `RDM Explorer v${info.version} is available!`
    link.href = info.url || '#'
    link.textContent = 'Download'
    link.onclick = null
    link.removeAttribute('target')
    link.style.display = ''
    if (info.url) link.setAttribute('target', '_blank')
  }
  document.getElementById('updateBanner').style.display = 'flex'
  document.body.classList.add('has-update')
}

function updateBannerProgress(p) {
  const el = document.getElementById('updateText')
  if (el) el.textContent = `Downloading update… ${p.percent}%`
}

// electron-updater finished downloading — offer a one-click restart
function showUpdateReady(info) {
  document.getElementById('updateText').textContent = `RDM Explorer v${info.version} is ready to install.`
  const link = document.getElementById('updateLink')
  link.style.display = ''
  link.textContent = 'Restart & Update'
  link.href = '#'
  link.removeAttribute('target')
  link.onclick = (e) => {
    e.preventDefault()
    link.textContent = 'Restarting…'
    window.rdm.installUpdate()
  }
  document.getElementById('updateBanner').style.display = 'flex'
  document.body.classList.add('has-update')
}

// ─── Scanning ─────────────────────────────────────────────────────────────────
const App = {
  async startScan() {
    if (State.scanning) return
    State.scanning = true
    State.isDemo   = false
    clearForScan()
    setScanningUI(true)
    log(`Starting scan (${protocolLabel()})…`)
    // Manual nodes are intentionally NOT pre-populated here.
    // They surface in the Nodes panel after the scan confirms (or fails to find) them.

    const sel = document.getElementById('ifaceSelect')
    const bindAddress = sel.value
    const broadcastAddress = sel.options[sel.selectedIndex].dataset.broadcast || '255.255.255.255'
    const subnetOverride = document.getElementById('subnetOverride').value.trim()
    await window.rdm.startScan(bindAddress, State.protocol, broadcastAddress, subnetOverride)
  },

  async addManualNode() {
    const ip   = document.getElementById('manualNodeIp').value.trim()
    const name = document.getElementById('manualNodeName').value.trim()
    if (!ip) return
    const res = await window.rdm.addManualNode(ip, name)
    if (res.ok) {
      document.getElementById('manualNodeIp').value   = ''
      document.getElementById('manualNodeName').value = ''
      const nodes = await window.rdm.getManualNodes()
      renderManualNodes(nodes)
      // Node will appear in the main Nodes panel after the next scan.
    } else {
      log(`Could not add node: ${res.error}`, 'err')
    }
  },

  async removeManualNode(ip) {
    await window.rdm.removeManualNode(ip)
    // Remove from the main Nodes panel by IP only.
    // The node might have been discovered via ArtPollReply (protocol = 'artnet')
    // rather than the manual placeholder — filtering by IP covers both cases.
    State.nodes = State.nodes.filter(n => n.ip !== ip)
    rerenderNodeList()
    const nodes = await window.rdm.getManualNodes()
    renderManualNodes(nodes)
  },

  // Click a sidebar node → show only its fixtures; click again to clear.
  toggleNodeFilter(ip) {
    State.nodeFilter = State.nodeFilter === ip ? null : ip
    rerenderNodeList()
    App.applyFilter()
  },

  loadDemo() {
    clearAll()
    State.isDemo = true
    setScanningUI(false)
    loadDemoData()
  },

  applyFilter() {
    const query    = document.getElementById('filterInput').value.toLowerCase()
    const category = document.getElementById('categoryFilter').value
    const sortBy   = document.getElementById('sortSelect').value

    State.filtered = State.devices.filter(d => {
      const haystack = [
        d.manufacturerLabel, d.deviceModelDescription,
        d.deviceLabel, d.uid, String(d.dmxStartAddress)
      ].join(' ').toLowerCase()
      const matchQ    = !query    || haystack.includes(query)
      const matchCat  = !category || d.productCategoryName === category
      const matchNode = !State.nodeFilter || d.nodeIP === State.nodeFilter
      return matchQ && matchCat && matchNode
    })

    const byAddr = (a, b) => (a.dmxStartAddress || 0) - (b.dmxStartAddress || 0)
    State.filtered.sort((a, b) => {
      if (sortBy === 'address')      return byAddr(a, b)
      if (sortBy === 'type')         return (a.productCategoryName || '').localeCompare(b.productCategoryName || '') || byAddr(a, b)
      if (sortBy === 'model')        return (a.deviceModelDescription || '').localeCompare(b.deviceModelDescription || '') || byAddr(a, b)
      if (sortBy === 'label')        return (a.deviceLabel || '').localeCompare(b.deviceLabel || '') || byAddr(a, b)
      if (sortBy === 'manufacturer') return (a.manufacturerLabel || '').localeCompare(b.manufacturerLabel || '') || byAddr(a, b)
      if (sortBy === 'node')         return (a.nodeIP || '').localeCompare(b.nodeIP || '', undefined, { numeric: true })
                                         || String(a.universe || '').localeCompare(String(b.universe || ''), undefined, { numeric: true })
                                         || byAddr(a, b)
      if (sortBy === 'uid')          return a.uid.localeCompare(b.uid)
      return 0
    })

    renderGrid()
  },

  // ── Modal ──────────────────────────────────────────────────────────────────
  openModal(uid) {
    const device = State.devices.find(d => d.uid === uid)
    if (!device) return
    State.activeDevice = device
    populateModal(device)
    document.getElementById('modal').style.display = 'flex'
    startDeviceDetail(device)
  },

  closeModal() {
    stopVitalsPoll()
    document.getElementById('modal').style.display = 'none'
    State.activeDevice = null
    hideFeedback()
  },

  async applyPersonality() {
    const device = State.activeDevice
    if (!device) return
    const val = parseInt(document.getElementById('editPersonality').value, 10)
    if (!val) return
    if (State.isDemo) {
      device.currentPersonality = val
      showFeedback(`Personality set to ${val}`, true)
      return
    }
    const res = await window.rdm.setDevicePersonality(device, val)
    if (res?.ok) {
      device.currentPersonality = val
      const p = (device._detail?.personalities || []).find(x => x.n === val)
      if (p) { device.personalityName = p.name; device.dmxFootprint = p.footprint }
      showFeedback(`Personality set to ${val}${p ? ' — ' + p.name : ''}`, true)
      updateCard(device)
    } else {
      showFeedback(res?.error || 'Failed to set personality', false)
    }
  },

  // ── Actions ────────────────────────────────────────────────────────────────
  async applyDmxAddress() {
    const device  = State.activeDevice
    if (!device) return
    const val = parseInt(document.getElementById('editAddress').value, 10)
    if (!val || val < 1 || val > 512) return showFeedback('Address must be 1–512', false)
    if (State.isDemo) {
      device.dmxStartAddress = val
      showFeedback(`DMX address set to ${val}`, true)
      updateCard(device)
      return
    }
    const res = await window.rdm.setDmxAddress(device, val)
    if (res?.ok) {
      device.dmxStartAddress = val
      showFeedback(`DMX address updated to ${val}`, true)
      updateCard(device)
    } else {
      showFeedback(`Failed: ${res?.error || 'no response'}`, false)
    }
  },

  async applyDeviceLabel() {
    const device = State.activeDevice
    if (!device) return
    const label = document.getElementById('editLabel').value.trim()
    if (!label) return showFeedback('Label cannot be empty', false)
    if (State.isDemo) {
      device.deviceLabel = label
      showFeedback(`Label set to "${label}"`, true)
      updateCard(device)
      return
    }
    const res = await window.rdm.setDeviceLabel(device, label)
    if (res?.ok) {
      device.deviceLabel = label
      showFeedback(`Label updated to "${label}"`, true)
      updateCard(device)
    } else {
      showFeedback(`Failed: ${res?.error || 'no response'}`, false)
    }
  },

  _setIdentifyUI(on) {
    document.getElementById('identifyOnBtn').classList.toggle('identify-active', on === true)
    document.getElementById('identifyOffBtn').classList.toggle('identify-active', on === false)
  },

  async identifyOn() {
    const device = State.activeDevice
    if (!device) return
    if (State.isDemo) { showFeedback('Identify ON (demo mode)', true); return }
    const res = await window.rdm.identifyDevice(device, true)
    if (res?.ok) { device._identify = true; App._setIdentifyUI(true); showFeedback('Identify ON', true) }
    else showFeedback(res?.error || 'Failed to send identify', false)
  },

  async identifyOff() {
    const device = State.activeDevice
    if (!device) return
    if (State.isDemo) { showFeedback('Identify OFF (demo mode)', true); return }
    const res = await window.rdm.identifyDevice(device, false)
    if (res?.ok) { device._identify = false; App._setIdentifyUI(false); showFeedback('Identify OFF', true) }
    else showFeedback(res?.error || 'Failed to send identify', false)
  },

  // Copy all log entries to the system clipboard
  copyLog() {
    const box = document.getElementById('logBox')
    const lines = Array.from(box.querySelectorAll('.log-entry'))
      .map(el => el.textContent)
      .join('\n')
    if (!lines) return
    navigator.clipboard.writeText(lines).then(() => {
      const btn = document.getElementById('copyLogBtn')
      const orig = btn.textContent
      btn.textContent = '✓ Copied'
      btn.classList.add('copied')
      setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied') }, 1800)
    }).catch(() => {
      // Fallback for environments without clipboard API
      const ta = document.createElement('textarea')
      ta.value = lines
      ta.style.position = 'fixed'
      ta.style.opacity  = '0'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
    })
  },

  // Toggle whether passive ArtDmx sources are shown in the node list
  toggleHidePassive() {
    State.hidePassive = !State.hidePassive
    const btn = document.getElementById('hidePassiveBtn')
    btn.classList.toggle('active', State.hidePassive)
    btn.textContent = State.hidePassive ? 'Show passive' : 'Hide passive'
    rerenderNodeList()
  },
}
window.App = App

// ─── Helpers ──────────────────────────────────────────────────────────────────

function protocolLabel() {
  if (State.protocol === 'artnet') return 'Art-Net'
  if (State.protocol === 'sacn')   return 'sACN'
  return 'Art-Net + sACN'
}

// ─── Scan lifecycle helpers ───────────────────────────────────────────────────
async function scanFinished(data, isError = false) {
  State.scanning = false
  setScanningUI(false)

  // Remove any nodes that were marked stale at scan start and never rediscovered.
  // (Nodes that responded this scan had their stale flag cleared by addNode().)
  const staleBefore = State.nodes.filter(n => n.stale).length
  State.nodes = State.nodes.filter(n => !n.stale)
  if (staleBefore > 0) rerenderNodeList()

  // After the scan, surface manual nodes in the Nodes panel.
  // - Nodes that responded to ArtPoll are already in State.nodes with real data.
  // - Nodes that the scan couldn't reach get added with notFound: true so the
  //   user can see which ones failed rather than them silently disappearing.
  const savedManual = await window.rdm.getManualNodes()
  let changed = false
  for (const mn of (savedManual || [])) {
    if (!State.nodes.find(n => n.ip === mn.ip)) {
      State.nodes.push({
        ip:          mn.ip,
        shortName:   mn.name || `Manual @ ${mn.ip}`,
        longName:    mn.name ? `${mn.name} (${mn.ip})` : `Manually added — ${mn.ip}`,
        protocol:    null,   // unknown — scan never confirmed the protocol
        supportsRDM: null,   // unknown — scan never confirmed RDM support
        manual:      true,
        notFound:    true,
      })
      changed = true
    }
  }
  if (changed) rerenderNodeList()

  if (!isError && data) {
    setStatus(`Found ${data.deviceCount} device(s)`, 'done')
  } else if (isError) {
    setStatus('Scan error', 'error')
  }

  // Show the log file path as a small pill below the Scan Log heading
  if (data && data.logPath) {
    const pill = document.getElementById('logFilePill')
    const text = document.getElementById('logFileText')
    if (pill && text) {
      // Show just the filename, not the full path
      const filename = data.logPath.split(/[/\\]/).pop()
      text.textContent = `📄 ${filename}`
      text.title       = data.logPath
      pill.style.display = 'block'
    }
  }
}

function setScanningUI(scanning) {
  const btn = document.getElementById('scanBtn')
  btn.disabled = scanning
  btn.classList.toggle('scanning', scanning)
  setStatus(scanning ? 'Scanning…' : (State.devices.length > 0 ? `Found ${State.devices.length}` : 'Ready'),
            scanning ? 'scanning' : (State.devices.length > 0 ? 'done' : 'idle'))
}

function setStatus(text, type) {
  document.getElementById('statusText').textContent = text
  const pill = document.getElementById('statusPill')
  pill.className = `status-pill status-${type}`
}

// ─── Nodes ────────────────────────────────────────────────────────────────────
// Protocol quality ranking — higher = more informative.
// An ArtPollReply ('artnet') carries name, universes, RDM flags, etc.
// A passive ArtDmx sniff ('artnet-passive') only has IP + universe numbers.
// We never replace a higher-quality entry with a lower-quality one.
// rdmnet ranks highest: a live RDMnet broker connection is confirmed RDM-capable,
// richer than anything learned from ArtPollReply/sACN packets for the same IP.
const PROTO_RANK = { rdmnet: 4, artnet: 3, sacn: 3, 'artnet-passive': 1 }

function addNode(node) {
  // Manual placeholder entries (protocol: null, manual: true) are deferred
  // entirely — scanFinished() surfaces them post-scan with real data or a
  // "not found" tag.  We use the manual flag rather than protocol because
  // protocol is null on these entries.
  if (node.manual) return

  const idx = State.nodes.findIndex(n => n.ip === node.ip)
  if (idx >= 0) {
    const existing = State.nodes[idx]
    // Only replace if the incoming entry is strictly better quality.
    // Example: GrandMA2 responds to ArtPoll (artnet, rank 3), then its
    // passive ArtDmx packets arrive (artnet-passive, rank 1) — the passive
    // entry must NOT overwrite the richer ArtPollReply data.
    const inRank  = PROTO_RANK[node.protocol]     || 0
    const exRank  = PROTO_RANK[existing.protocol] || 0
    if (inRank <= exRank) {
      // Lower-quality data — don't overwrite, but DO clear the stale flag so
      // the node isn't pruned at scan end (it's clearly alive if it's sending).
      if (existing.stale) {
        State.nodes[idx] = { ...existing, stale: false }
        rerenderNodeList()
      }
      return
    }
    State.nodes[idx] = { ...node, stale: false }
  } else {
    State.nodes.push(node)
  }
  rerenderNodeList()
}

function buildNodeLi(node) {
  let proto, protoClass, rdmTag
  if (node.protocol === 'sacn') {
    proto = 'sACN'
    protoClass = 'sacn'
    rdmTag = '<div class="node-rdm node-sacn-tag">sACN</div>'
  } else if (node.protocol === 'artnet-passive') {
    proto = 'ArtDmx'
    protoClass = 'artnet-passive'
    const uniCount = node.universes ? node.universes.length : 0
    const pktCount = node.packetCount ? ` · ${node.packetCount} pkts` : ''
    rdmTag = `<div class="node-rdm node-passive-tag">${uniCount} uni${pktCount}</div>`
  } else if (node.manual) {
    // Manual node whose protocol was never confirmed by a scan reply.
    proto = 'Manual'
    protoClass = 'artnet-manual'
    rdmTag = node.notFound
      ? '<div class="node-manual-tag node-not-found-tag">⚠ not found</div>'
      : '<div class="node-manual-tag">manual</div>'
  } else {
    proto = 'Art-Net'
    protoClass = 'artnet'
    rdmTag = `<div class="node-rdm">${node.supportsRDM ? '&#10003; RDM' : '&#9675; No RDM'}</div>`
  }

  const li = document.createElement('li')
  const selected = State.nodeFilter === node.ip
  li.className = `node-item node-real node-clickable${node.stale ? ' node-stale' : ''}${selected ? ' node-selected' : ''}`
  li.title = selected ? 'Showing only this node\u2019s fixtures — click to show all'
                      : 'Click to show only this node\u2019s fixtures'
  li.innerHTML = `
    <div class="node-name">${escHtml(node.shortName)}</div>
    <div class="node-ip">${escHtml(node.ip)}</div>
    <div class="node-proto-row">
      <span class="node-proto-badge proto-badge-${protoClass}">${escHtml(proto)}</span>
      ${node.stale ? '<div class="node-rdm node-checking-tag">checking…</div>' : rdmTag}
      ${selected ? '<div class="node-filter-tag">filtering</div>' : ''}
    </div>
  `
  li.addEventListener('click', () => App.toggleNodeFilter(node.ip))
  return li
}

function rerenderNodeList() {
  const list  = document.getElementById('nodeList')
  list.innerHTML = ''

  const visible = State.nodes.filter(n =>
    !(State.hidePassive && n.protocol === 'artnet-passive')
  )

  if (visible.length === 0) {
    list.innerHTML = '<li class="node-item node-empty">No nodes found yet</li>'
  } else {
    visible.forEach(n => list.appendChild(buildNodeLi(n)))
  }

  // Badge shows total regardless of filter so user knows how many exist
  document.getElementById('nodeCount').textContent = State.nodes.length
}

// ─── Devices ─────────────────────────────────────────────────────────────────
function addDevice(device) {
  const idx = State.devices.findIndex(d => d.uid === device.uid)
  if (idx >= 0) {
    // Same device re-emitted with richer data (post-scan label backfill) —
    // merge non-empty fields and refresh its card in place.
    const merged = { ...State.devices[idx] }
    for (const [k, v] of Object.entries(device)) {
      if (v !== null && v !== undefined && v !== '') merged[k] = v
    }
    State.devices[idx] = merged
    updateCard(merged)
    updateCategoryFilter()
    App.applyFilter()
    return
  }
  State.devices.push(device)
  updateCategoryFilter()
  App.applyFilter()
  updateDeviceCount()
}

function updateCard(device) {
  const existing = document.getElementById(`card-${device.uid.replace(':', '-')}`)
  if (existing) existing.replaceWith(buildCard(device))
}

function updateDeviceCount() {
  const el = document.getElementById('deviceCount')
  el.textContent = `${State.devices.length} device${State.devices.length !== 1 ? 's' : ''}`
}

function updateCategoryFilter() {
  const sel = document.getElementById('categoryFilter')
  const current = sel.value
  const cats = [...new Set(State.devices.map(d => d.productCategoryName).filter(Boolean))].sort()
  sel.innerHTML = '<option value="">All</option>' +
    cats.map(c => `<option value="${escHtml(c)}">${escHtml(c)}</option>`).join('')
  sel.value = current
}

// ─── Grid Rendering ───────────────────────────────────────────────────────────
function renderGrid() {
  const grid  = document.getElementById('deviceGrid')
  const empty = document.getElementById('emptyState')

  if (State.filtered.length === 0) {
    grid.style.display  = 'none'
    empty.style.display = State.devices.length === 0 ? 'flex' : 'none'
    if (State.devices.length > 0) {
      empty.style.display = 'flex'
      empty.querySelector('.empty-title').textContent = 'No devices match the current filter'
      empty.querySelector('.empty-sub').textContent   = 'Try clearing the search or changing the category filter.'
    }
    return
  }

  empty.style.display = 'none'
  grid.style.display  = 'grid'
  grid.innerHTML      = State.filtered.map(d => buildCard(d).outerHTML).join('')
}

function buildCard(device) {
  const mfr   = device.manufacturerLabel      || '—'
  const model = device.deviceModelDescription || device.uid
  const label = device.deviceLabel             || ''
  const addr  = device.dmxStartAddress != null ? String(device.dmxStartAddress) : '—'
  const foot  = device.dmxFootprint != null    ? String(device.dmxFootprint)    : '—'
  const pers  = device.personalityName         || (device.currentPersonality ? `Mode ${device.currentPersonality}` : '—')
  const cat   = device.productCategoryName     || 'Fixture'
  const proto = device.protocol === 'sacn' ? 'sACN'
              : device.protocol === 'rdmnet-llrp' ? 'LLRP'
              : device.protocol === 'rdmnet-rpt' ? 'RPT'
              : 'Art-Net'

  const catClass = categoryClass(cat)

  const card = document.createElement('div')
  card.id        = `card-${device.uid.replace(':', '-')}`
  card.className = `device-card ${catClass}`
  card.dataset.uid = device.uid   // click handled by grid-level delegation (survives innerHTML re-renders)
  card.innerHTML = `
    <div class="card-top-row">
      <div class="card-manufacturer">${escHtml(mfr)}</div>
      <span class="card-proto-badge proto-badge-${device.protocol || 'artnet'}">${escHtml(proto)}</span>
    </div>
    <div class="card-model">${escHtml(model)}</div>
    <div class="card-label">${escHtml(label)}</div>
    <div class="card-meta">
      <div class="card-meta-item">
        <span class="meta-key">DMX Addr</span>
        <span class="meta-value">${escHtml(addr)}</span>
      </div>
      <div class="card-meta-item">
        <span class="meta-key">Footprint</span>
        <span class="meta-value">${escHtml(foot)}</span>
      </div>
      <div class="card-meta-item" style="grid-column:1/-1">
        <span class="meta-key">Personality</span>
        <span class="meta-value" style="font-size:11px">${escHtml(pers)}</span>
      </div>
    </div>
    <div class="card-uid">${escHtml(device.uid)}</div>
  `
  return card
}

function categoryClass(cat) {
  const c = cat.toLowerCase()
  if (c.includes('moving'))      return 'cat-moving'
  if (c.includes('led') || c.includes('fixture'))  return 'cat-led'
  if (c.includes('strobe'))      return 'cat-strobe'
  if (c.includes('dimmer'))      return 'cat-dimmer'
  if (c.includes('atmospheric') || c.includes('fog') || c.includes('haze')) return 'cat-atmospheric'
  return 'cat-other'
}

// ─── Modal Population ────────────────────────────────────────────────────────
function populateModal(device) {
  document.getElementById('modalCategory').textContent = device.productCategoryName || 'Fixture'
  document.getElementById('modalTitle').textContent    = device.deviceModelDescription || device.uid
  document.getElementById('modalSubtitle').textContent = device.manufacturerLabel || ''
  document.getElementById('modalUid').textContent      = `UID: ${device.uid}`

  const items = [
    ['DMX Start Address',  device.dmxStartAddress],
    ['DMX Footprint',      device.dmxFootprint],
    ['Personality',        device.currentPersonality && device.personalityName
                             ? `${device.currentPersonality} — ${device.personalityName}`
                             : device.currentPersonality || '—'],
    ['Personality Count',  device.personalityCount],
    ['Software Version',   device.softwareVersionLabel],
    ['Model ID',           device.deviceModelId != null ? `0x${device.deviceModelId.toString(16).toUpperCase().padStart(4,'0')}` : null],
    ['Product Category',   device.productCategoryName],
    ['Sub-Devices',        device.subDeviceCount],
    ['Sensors',            device.sensorCount],
    ['Node',               device.nodeName ? `${device.nodeName} (${device.nodeIP})` : device.nodeIP],
    ['Universe',           device.universe],
    ['Protocol',           device.protocol === 'sacn' ? 'sACN (E1.31)'
                           : device.protocol === 'rdmnet-llrp' ? 'RDMnet (LLRP)'
                           : device.protocol === 'rdmnet-rpt' ? 'RDMnet (RPT/Broker)'
                           : 'Art-Net'],
    ['Transport',          device.transport],
  ]

  document.getElementById('modalInfoList').innerHTML = items
    .filter(([, v]) => v != null && v !== '')
    .map(([k, v]) => `<dt>${escHtml(String(k))}</dt><dd>${escHtml(String(v))}</dd>`)
    .join('')

  document.getElementById('editAddress').value = device.dmxStartAddress || ''
  document.getElementById('editLabel').value   = device.deviceLabel || ''
  App._setIdentifyUI(device._identify === true ? true : false)

  hideFeedback()
}

// ─── Fixture Detail: vitals + status polling ─────────────────────────────────
//
// When the fixture modal opens we fetch static detail once (personality list,
// sensor definitions), then poll sensor values / vitals / status messages every
// few seconds while the modal stays open.  A token guards against stale async
// updates after the modal is closed or another fixture is opened.

let _vitalsTimer = null
let _vitalsToken = 0

function stopVitalsPoll() {
  _vitalsToken++
  if (_vitalsTimer) { clearTimeout(_vitalsTimer); _vitalsTimer = null }
}

async function startDeviceDetail(device) {
  stopVitalsPoll()
  const token = _vitalsToken

  document.getElementById('vitalsChips').innerHTML     = '<span class="vitals-loading">Reading device…</span>'
  document.getElementById('sensorTableWrap').innerHTML = ''
  document.getElementById('statusMsgWrap').innerHTML   = ''
  document.getElementById('personalityGroup').style.display = 'none'

  if (State.isDemo) {
    renderVitals(device,
      { personalities: [{ n:1, footprint:28, name:'Standard' }, { n:2, footprint:40, name:'Extended' }],
        sensors: [{ num:0, typeName:'Temperature', unit:'°C', prefixMult:1, description:'Base Temp', rangeMin:-10, rangeMax:90, normalMin:0, normalMax:70 }] },
      { sensors: [{ num:0, present:42, lowest:21, highest:58, recorded:0 }],
        vitals: { deviceHours: 1234, lampState: 'On', powerCycles: 87, dmxStartAddress: device.dmxStartAddress },
        statusMessages: [] })
    populatePersonalitySelect(device, [{ n:1, footprint:28, name:'Standard' }, { n:2, footprint:40, name:'Extended' }])
    return
  }

  // One-time static detail (cached per device object)
  if (!device._detail) {
    const res = await window.rdm.getDeviceDetail(device)
    if (token !== _vitalsToken) return
    device._detail = res?.ok ? res.detail : { personalities: [], sensors: [] }
  }
  populatePersonalitySelect(device, device._detail.personalities)

  const pollOnce = async () => {
    if (token !== _vitalsToken) return
    if (State.scanning) {                     // don't interleave with an active scan
      _vitalsTimer = setTimeout(pollOnce, 3000)
      return
    }
    const sensorNums = (device._detail.sensors || []).map(sd => sd.num)
    const res = await window.rdm.pollDeviceVitals(device, sensorNums)
    if (token !== _vitalsToken) return
    if (res?.ok) renderVitals(device, device._detail, res.vitals)
    else document.getElementById('vitalsChips').innerHTML =
      `<span class="vitals-loading">No response — device may be offline (${escHtml(res?.error || 'timeout')})</span>`
    _vitalsTimer = setTimeout(pollOnce, 4000)
  }
  pollOnce()
}

function populatePersonalitySelect(device, personalities) {
  if (!personalities || personalities.length === 0) return
  const sel = document.getElementById('editPersonality')
  sel.innerHTML = personalities.map(p =>
    `<option value="${p.n}" ${p.n === device.currentPersonality ? 'selected' : ''}>` +
    `${p.n} — ${escHtml(p.name || 'Mode ' + p.n)} (${p.footprint} ch)</option>`
  ).join('')
  document.getElementById('personalityGroup').style.display = ''
}

function _fmtSensorVal(raw, def) {
  if (raw == null) return '—'
  const v = raw * (def?.prefixMult ?? 1)
  const rounded = Math.abs(v) >= 100 ? Math.round(v) : Math.round(v * 10) / 10
  return `${rounded}${def?.unit ? ' ' + def.unit : ''}`
}

function renderVitals(device, detail, data) {
  // ── Vitals chips ──
  const v = data.vitals || {}
  const chips = []
  const chip = (label, val, cls = '') => {
    if (val == null || val === '') return
    chips.push(`<div class="vital-chip ${cls}"><span class="vital-label">${escHtml(label)}</span><span class="vital-value">${escHtml(String(val))}</span></div>`)
  }
  chip('Device Hours', v.deviceHours != null ? v.deviceHours.toLocaleString() : null)
  chip('Lamp Hours',   v.lampHours   != null ? v.lampHours.toLocaleString()   : null)
  chip('Lamp State',   v.lampState, v.lampState === 'Error' ? 'chip-err' : '')
  chip('Lamp Strikes', v.lampStrikes != null ? v.lampStrikes.toLocaleString() : null)
  chip('Power Cycles', v.powerCycles != null ? v.powerCycles.toLocaleString() : null)
  chip('DMX Address',  v.dmxStartAddress)
  document.getElementById('vitalsChips').innerHTML =
    chips.length ? chips.join('') : '<span class="vitals-loading">This fixture reports no vitals</span>'

  // Live-update the address in device state if it changed externally
  if (v.dmxStartAddress != null && v.dmxStartAddress !== device.dmxStartAddress) {
    device.dmxStartAddress = v.dmxStartAddress
    updateCard(device)
  }

  // ── Sensors table ──
  const defs = new Map((detail.sensors || []).map(d => [d.num, d]))
  const rows = (data.sensors || []).map(sv => {
    const def = defs.get(sv.num) || {}
    const outOfNormal = def.normalMax !== undefined && def.normalMax !== def.normalMin &&
                        (sv.present > def.normalMax || sv.present < def.normalMin)
    return `<tr class="${outOfNormal ? 'sensor-alert' : ''}">
      <td>${escHtml(def.description || def.typeName || ('Sensor ' + sv.num))}</td>
      <td class="sensor-val">${_fmtSensorVal(sv.present, def)}</td>
      <td>${_fmtSensorVal(sv.lowest, def)} / ${_fmtSensorVal(sv.highest, def)}</td>
      <td>${def.normalMin !== undefined ? _fmtSensorVal(def.normalMin, def) + ' – ' + _fmtSensorVal(def.normalMax, def) : '—'}</td>
    </tr>`
  }).join('')
  document.getElementById('sensorTableWrap').innerHTML = rows
    ? `<table class="sensor-table">
         <thead><tr><th>Sensor</th><th>Now</th><th>Low / High</th><th>Normal Range</th></tr></thead>
         <tbody>${rows}</tbody></table>`
    : ''

  // ── Status / error messages ──
  const msgs = data.statusMessages || []
  const badge = (t) => t.includes('Error') ? 'st-err' : t.includes('Warning') ? 'st-warn' : 'st-adv'
  document.getElementById('statusMsgWrap').innerHTML = msgs.length
    ? `<div class="status-list">` + msgs.map(m =>
        `<div class="status-msg ${badge(m.typeName)}">
           <span class="status-badge">${escHtml(m.typeName)}</span>
           <span class="status-text">${escHtml(m.text)}</span>
           ${m.subDevice ? `<span class="status-sub">sub-device ${m.subDevice}</span>` : ''}
         </div>`).join('') + `</div>`
    : `<div class="status-clear">✓ No active status or error messages</div>`
}

// ─── Feedback ────────────────────────────────────────────────────────────────
function showFeedback(msg, ok) {
  const el = document.getElementById('setFeedback')
  el.textContent  = msg
  el.className    = `set-feedback ${ok ? 'ok' : 'err'}`
  el.style.display = 'block'
}
function hideFeedback() {
  const el = document.getElementById('setFeedback')
  el.style.display = 'none'
}

// ─── Log ─────────────────────────────────────────────────────────────────────
const LOG_MAX_ENTRIES = 600   // keep the DOM bounded during long sessions
function log(msg, type = '') {
  const box  = document.getElementById('logBox')
  const line = document.createElement('div')
  line.className   = `log-entry ${type ? 'log-' + type : ''}`
  line.textContent = msg
  box.appendChild(line)
  while (box.childElementCount > LOG_MAX_ENTRIES) box.removeChild(box.firstChild)
  box.scrollTop = box.scrollHeight
}

// ─── Clear ────────────────────────────────────────────────────────────────────

// Called at the START of a new scan.
// Keeps existing nodes visible (dimmed) so they don't flash out — the scan
// will un-stale any it rediscovers.  Nodes not found by scan end are pruned
// in scanFinished().  Everything else (devices, log, filter) is reset fresh.
function clearForScan() {
  State.nodeFilter = null
  // Mark every known node as stale — it will be un-staled when nodeFound fires for it
  State.nodes.forEach(n => { n.stale = true })
  rerenderNodeList()

  State.devices  = []
  State.filtered = []
  document.getElementById('deviceGrid').innerHTML     = ''
  document.getElementById('deviceGrid').style.display = 'none'
  document.getElementById('emptyState').style.display = 'flex'
  document.getElementById('emptyState').querySelector('.empty-title').textContent = 'No devices discovered yet'
  document.getElementById('emptyState').querySelector('.empty-sub').innerHTML =
    'Select a network interface above and click <strong>Scan Network</strong>.<br>No hardware? Hit <strong>Demo</strong> to explore the interface.'
  document.getElementById('categoryFilter').innerHTML = '<option value="">All</option>'
  document.getElementById('logBox').innerHTML         = ''
  document.getElementById('filterInput').value        = ''
  const pill = document.getElementById('logFilePill')
  if (pill) pill.style.display = 'none'
  updateDeviceCount()
}

function clearAll() {
  State.nodeFilter = null
  State.devices  = []
  State.nodes    = []
  State.filtered = []
  rerenderNodeList()
  document.getElementById('nodeCount').textContent    = '0'
  document.getElementById('deviceGrid').innerHTML     = ''
  document.getElementById('deviceGrid').style.display = 'none'
  document.getElementById('emptyState').style.display = 'flex'
  document.getElementById('emptyState').querySelector('.empty-title').textContent = 'No devices discovered yet'
  document.getElementById('emptyState').querySelector('.empty-sub').innerHTML =
    'Select a network interface above and click <strong>Scan Network</strong>.<br>No hardware? Hit <strong>Demo</strong> to explore the interface.'
  document.getElementById('categoryFilter').innerHTML = '<option value="">All</option>'
  document.getElementById('logBox').innerHTML         = ''
  document.getElementById('filterInput').value        = ''
  // Hide log file pill when starting a fresh scan
  const pill = document.getElementById('logFilePill')
  if (pill) pill.style.display = 'none'
  updateDeviceCount()
}

// ─── Demo Data ────────────────────────────────────────────────────────────────
function loadDemoData() {
  log('Loading demo data…')

  // ── Art-Net nodes ─────────────────────────────────────────────────────────
  const demoNodes = [
    { ip: '192.168.1.101', shortName: 'Pathport Node A', longName: 'Pathway Pathport 8 — Stage Left', supportsRDM: true, universes: [{net:0,sub:0,uni:0},{net:0,sub:0,uni:1}], protocol: 'artnet' },
    { ip: '192.168.1.102', shortName: 'Pathport Node B', longName: 'Pathway Pathport 8 — Stage Right', supportsRDM: true, universes: [{net:0,sub:0,uni:2}], protocol: 'artnet' },
  ]

  // ── sACN sources ──────────────────────────────────────────────────────────
  const demoSACNNodes = [
    { ip: '192.168.1.200', shortName: 'ETC Eos Ti', longName: 'ETC Eos Ti — Main Console', supportsRDM: false, universes: [{net:0,sub:0,uni:1},{net:0,sub:0,uni:2},{net:0,sub:0,uni:3},{net:0,sub:0,uni:4}], protocol: 'sacn', priority: 100 },
    { ip: '192.168.1.201', shortName: 'ChamSys MQ500', longName: 'ChamSys MagicQ MQ500 — Backup', supportsRDM: false, universes: [{net:0,sub:0,uni:1},{net:0,sub:0,uni:2}], protocol: 'sacn', priority: 90 },
    { ip: '192.168.1.150', shortName: 'ETC Response Mk2', longName: 'ETC Response Mk2 Gateway — Truss 1', supportsRDM: false, universes: [{net:0,sub:0,uni:1},{net:0,sub:0,uni:2},{net:0,sub:0,uni:5},{net:0,sub:0,uni:6}], protocol: 'sacn', priority: 100 },
  ]

  // ── RDM devices (discovered via Art-Net) ──────────────────────────────────
  const demoDevices = [
    { uid: '0001:12AB3400', manufacturerLabel: 'Martin', deviceModelDescription: 'MAC Aura XB', deviceLabel: 'SR Wash 1', dmxStartAddress: 1,   dmxFootprint: 40, currentPersonality: 3, personalityName: 'Extended',       personalityCount: 4, productCategoryName: 'Fixture — Moving Yoke', universe: '0.0.0', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '1.4.2', protocol: 'artnet' },
    { uid: '0001:12AB3401', manufacturerLabel: 'Martin', deviceModelDescription: 'MAC Aura XB', deviceLabel: 'SR Wash 2', dmxStartAddress: 41,  dmxFootprint: 40, currentPersonality: 3, personalityName: 'Extended',       personalityCount: 4, productCategoryName: 'Fixture — Moving Yoke', universe: '0.0.0', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '1.4.2', protocol: 'artnet' },
    { uid: '0001:12AB3402', manufacturerLabel: 'Martin', deviceModelDescription: 'MAC Aura XB', deviceLabel: 'SL Wash 1', dmxStartAddress: 81,  dmxFootprint: 40, currentPersonality: 3, personalityName: 'Extended',       personalityCount: 4, productCategoryName: 'Fixture — Moving Yoke', universe: '0.0.0', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '1.4.2', protocol: 'artnet' },
    { uid: '0001:12AB3403', manufacturerLabel: 'Martin', deviceModelDescription: 'MAC Aura XB', deviceLabel: 'SL Wash 2', dmxStartAddress: 121, dmxFootprint: 40, currentPersonality: 3, personalityName: 'Extended',       personalityCount: 4, productCategoryName: 'Fixture — Moving Yoke', universe: '0.0.0', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '1.4.2', protocol: 'artnet' },
    { uid: '4752:00010001', manufacturerLabel: 'Robe',   deviceModelDescription: 'Robin 300E Spot',  deviceLabel: 'Spot 1',    dmxStartAddress: 161, dmxFootprint: 28, currentPersonality: 1, personalityName: 'Mode 1 (28ch)', personalityCount: 3, productCategoryName: 'Fixture — Moving Yoke', universe: '0.0.0', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '2.1.0', protocol: 'artnet' },
    { uid: '4752:00010002', manufacturerLabel: 'Robe',   deviceModelDescription: 'Robin 300E Spot',  deviceLabel: 'Spot 2',    dmxStartAddress: 189, dmxFootprint: 28, currentPersonality: 1, personalityName: 'Mode 1 (28ch)', personalityCount: 3, productCategoryName: 'Fixture — Moving Yoke', universe: '0.0.0', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '2.1.0', protocol: 'artnet' },
    { uid: '4752:00010003', manufacturerLabel: 'Robe',   deviceModelDescription: 'Robin 300E Spot',  deviceLabel: 'Spot 3',    dmxStartAddress: 217, dmxFootprint: 28, currentPersonality: 1, personalityName: 'Mode 1 (28ch)', personalityCount: 3, productCategoryName: 'Fixture — Moving Yoke', universe: '0.0.0', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '2.1.0', protocol: 'artnet' },
    { uid: '1A7C:00000010', manufacturerLabel: 'Chauvet Professional', deviceModelDescription: 'Ovation E-910FC', deviceLabel: 'FOH L',  dmxStartAddress: 1,   dmxFootprint: 17, currentPersonality: 2, personalityName: '17ch RGBALC',  personalityCount: 4, productCategoryName: 'Fixture',               universe: '0.0.1', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '3.0.1', protocol: 'artnet' },
    { uid: '1A7C:00000011', manufacturerLabel: 'Chauvet Professional', deviceModelDescription: 'Ovation E-910FC', deviceLabel: 'FOH R',  dmxStartAddress: 18,  dmxFootprint: 17, currentPersonality: 2, personalityName: '17ch RGBALC',  personalityCount: 4, productCategoryName: 'Fixture',               universe: '0.0.1', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '3.0.1', protocol: 'artnet' },
    { uid: '6C74:00001001', manufacturerLabel: 'ETC',    deviceModelDescription: 'Source Four LED Series 3', deviceLabel: 'Key Light L', dmxStartAddress: 35,  dmxFootprint: 8,  currentPersonality: 1, personalityName: '8ch',          personalityCount: 2, productCategoryName: 'Fixture',               universe: '0.0.1', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '4.2.0', protocol: 'artnet' },
    { uid: '6C74:00001002', manufacturerLabel: 'ETC',    deviceModelDescription: 'Source Four LED Series 3', deviceLabel: 'Key Light R', dmxStartAddress: 43,  dmxFootprint: 8,  currentPersonality: 1, personalityName: '8ch',          personalityCount: 2, productCategoryName: 'Fixture',               universe: '0.0.1', nodeName: 'Pathport Node A', nodeIP: '192.168.1.101', softwareVersionLabel: '4.2.0', protocol: 'artnet' },
    { uid: '4D41:00000001', manufacturerLabel: 'Martin', deviceModelDescription: 'RUSH Strobe 1 BMD', deviceLabel: 'Strobe DSR', dmxStartAddress: 1,   dmxFootprint: 5,  currentPersonality: 1, personalityName: '5ch',          personalityCount: 2, productCategoryName: 'Fixture',               universe: '0.0.2', nodeName: 'Pathport Node B', nodeIP: '192.168.1.102', softwareVersionLabel: '1.0.5', protocol: 'artnet' },
    { uid: '4D41:00000002', manufacturerLabel: 'Martin', deviceModelDescription: 'RUSH Strobe 1 BMD', deviceLabel: 'Strobe DSL', dmxStartAddress: 6,   dmxFootprint: 5,  currentPersonality: 1, personalityName: '5ch',          personalityCount: 2, productCategoryName: 'Fixture',               universe: '0.0.2', nodeName: 'Pathport Node B', nodeIP: '192.168.1.102', softwareVersionLabel: '1.0.5', protocol: 'artnet' },
    { uid: '414E:00000001', manufacturerLabel: 'Antari', deviceModelDescription: 'Z-1500 II',     deviceLabel: 'Hazer SR',  dmxStartAddress: 20,  dmxFootprint: 4,  currentPersonality: 1, personalityName: '4ch',          personalityCount: 1, productCategoryName: 'Atmospheric — Haze',    universe: '0.0.2', nodeName: 'Pathport Node B', nodeIP: '192.168.1.102', softwareVersionLabel: '2.0', protocol: 'artnet' },
  ]

  // Add Art-Net nodes
  demoNodes.forEach(n => addNode(n))
  log(`Found ${demoNodes.length} Art-Net nodes.`)

  // Add sACN sources
  demoSACNNodes.forEach(n => addNode(n))
  log(`Found ${demoSACNNodes.length} sACN sources.`)

  // Add RDM devices with staggered animation
  let i = 0
  function addNext() {
    if (i < demoDevices.length) {
      addDevice(demoDevices[i])
      log(`  Found: ${demoDevices[i].manufacturerLabel} ${demoDevices[i].deviceModelDescription} @ ${demoDevices[i].dmxStartAddress}`)
      i++
      setTimeout(addNext, 60)
    } else {
      log(`Scan complete — ${demoDevices.length} devices loaded.`, 'done')
      setStatus(`Demo: ${demoDevices.length} devices`, 'done')
    }
  }
  setTimeout(addNext, 200)
}

// ─── Utilities ────────────────────────────────────────────────────────────────
function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
