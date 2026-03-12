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
}

// ─── Init ─────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
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

  // Update banner
  document.getElementById('updateDismiss').addEventListener('click', () => {
    document.getElementById('updateBanner').style.display = 'none'
    document.body.classList.remove('has-update')
  })

  // Copy log to clipboard
  document.getElementById('copyLogBtn').addEventListener('click', () => App.copyLog())

  // Hide / show passive ArtDmx sources in the node list
  document.getElementById('hidePassiveBtn').addEventListener('click', () => App.toggleHidePassive())
})

// ─── Manual Nodes ─────────────────────────────────────────────────────────────
async function loadManualNodes() {
  const nodes = await window.rdm.getManualNodes()
  renderManualNodes(nodes)
  // Also populate the main Nodes list with any already-saved manual nodes
  for (const n of (nodes || [])) {
    addNode({
      ip:          n.ip,
      shortName:   n.name || `Manual @ ${n.ip}`,
      longName:    n.name ? `${n.name} (${n.ip})` : `Manually added — ${n.ip}`,
      protocol:    'artnet-manual',
      supportsRDM: true,
      manual:      true,
      universes:   [],
    })
  }
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
  document.getElementById('updateText').textContent = `RDM Explorer v${info.version} is available!`
  const link = document.getElementById('updateLink')
  link.href = info.url
  link.textContent = 'Download'
  document.getElementById('updateBanner').style.display = 'flex'
  document.body.classList.add('has-update')
}

// ─── Scanning ─────────────────────────────────────────────────────────────────
const App = {
  async startScan() {
    if (State.scanning) return
    State.scanning = true
    State.isDemo   = false
    clearAll()
    setScanningUI(true)
    log(`Starting scan (${protocolLabel()})…`)
    // Re-add manually configured nodes to the Nodes list so they're visible
    // during the scan, even before the scanner emits nodeFound for them.
    const savedManual = await window.rdm.getManualNodes()
    for (const n of (savedManual || [])) {
      addNode({
        ip:          n.ip,
        shortName:   n.name || `Manual @ ${n.ip}`,
        longName:    n.name ? `${n.name} (${n.ip})` : `Manually added — ${n.ip}`,
        protocol:    'artnet-manual',
        supportsRDM: true,
        manual:      true,
        universes:   [],
      })
    }

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
      // Surface this node in the main Nodes list immediately (don't wait for scan)
      addNode({
        ip,
        shortName:   name || `Manual @ ${ip}`,
        longName:    name ? `${name} (${ip})` : `Manually added — ${ip}`,
        protocol:    'artnet-manual',
        supportsRDM: true,
        manual:      true,
        universes:   [],
      })
    } else {
      log(`Could not add node: ${res.error}`, 'err')
    }
  },

  async removeManualNode(ip) {
    await window.rdm.removeManualNode(ip)
    // Remove from the main Nodes list as well
    State.nodes = State.nodes.filter(n => !(n.ip === ip && n.protocol === 'artnet-manual'))
    rerenderNodeList()
    const nodes = await window.rdm.getManualNodes()
    renderManualNodes(nodes)
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
      const matchQ   = !query    || haystack.includes(query)
      const matchCat = !category || d.productCategoryName === category
      return matchQ && matchCat
    })

    State.filtered.sort((a, b) => {
      if (sortBy === 'address')      return (a.dmxStartAddress || 0) - (b.dmxStartAddress || 0)
      if (sortBy === 'label')        return (a.deviceLabel || '').localeCompare(b.deviceLabel || '')
      if (sortBy === 'manufacturer') return (a.manufacturerLabel || '').localeCompare(b.manufacturerLabel || '')
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
  },

  closeModal() {
    document.getElementById('modal').style.display = 'none'
    State.activeDevice = null
    hideFeedback()
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

  async identifyOn() {
    const device = State.activeDevice
    if (!device) return
    if (State.isDemo) { showFeedback('Identify ON (demo mode)', true); return }
    const res = await window.rdm.identifyDevice(device, true)
    res?.ok ? showFeedback('Identify ON', true) : showFeedback('Failed to send identify', false)
  },

  async identifyOff() {
    const device = State.activeDevice
    if (!device) return
    if (State.isDemo) { showFeedback('Identify OFF (demo mode)', true); return }
    const res = await window.rdm.identifyDevice(device, false)
    res?.ok ? showFeedback('Identify OFF', true) : showFeedback('Failed to send identify', false)
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
function scanFinished(data, isError = false) {
  State.scanning = false
  setScanningUI(false)
  if (!isError && data) {
    setStatus(`Found ${data.deviceCount} device(s)`, 'done')
  } else if (isError) {
    setStatus('Scan error', 'error')
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
function addNode(node) {
  // Avoid duplicates by ip+protocol
  if (State.nodes.find(n => n.ip === node.ip && n.protocol === node.protocol)) return
  State.nodes.push(node)
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
  } else if (node.protocol === 'artnet-manual') {
    proto = 'Manual'
    protoClass = 'artnet-manual'
    rdmTag = '<div class="node-manual-tag">manual · RDM</div>'
  } else {
    proto = 'Art-Net'
    protoClass = 'artnet'
    rdmTag = `<div class="node-rdm">${node.supportsRDM ? '&#10003; RDM' : '&#9675; No RDM'}</div>`
  }

  const li = document.createElement('li')
  li.className = 'node-item node-real'
  li.innerHTML = `
    <div class="node-name">${escHtml(node.shortName)}</div>
    <div class="node-ip">${escHtml(node.ip)}</div>
    <div class="node-proto-row">
      <span class="node-proto-badge proto-badge-${protoClass}">${escHtml(proto)}</span>
      ${rdmTag}
    </div>
  `
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
  if (State.devices.find(d => d.uid === device.uid)) return
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
  card.addEventListener('click', () => App.openModal(device.uid))
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

  hideFeedback()
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
function log(msg, type = '') {
  const box  = document.getElementById('logBox')
  const line = document.createElement('div')
  line.className   = `log-entry ${type ? 'log-' + type : ''}`
  line.textContent = msg
  box.appendChild(line)
  box.scrollTop = box.scrollHeight
}

// ─── Clear ────────────────────────────────────────────────────────────────────
function clearAll() {
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
