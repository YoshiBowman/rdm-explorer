/**
 * main.js
 * Electron main process.
 * Creates the browser window, handles IPC, drives the Scanner, and checks for updates.
 */

'use strict'

const { app, BrowserWindow, ipcMain } = require('electron')
const path  = require('path')
const os    = require('os')
const https = require('https')
const Scanner = require('./src/scanner')

const PKG = require('./package.json')

let mainWindow  = null
let scanner     = null
let manualNodes = []   // persists across scans: [{ ip, name, universes }]

// ─── Window ──────────────────────────────────────────────────────────────────

function createWindow() {
  mainWindow = new BrowserWindow({
    width:  1280,
    height: 820,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#111827',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
    },
    show: false,
  })

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'))

  mainWindow.once('ready-to-show', () => {
    mainWindow.show()
    // Check for updates a few seconds after launch
    setTimeout(checkForUpdates, 4000)
  })

  mainWindow.on('closed', () => {
    mainWindow = null
    if (scanner) { scanner.stop(); scanner = null }
  })
}

app.whenReady().then(createWindow)

// ─── Crash safety ─────────────────────────────────────────────────────────────
// Catch anything that escapes try/catch blocks so it shows up in the scan log
// instead of silently killing the app.

process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err)
  send('scan-error', { message: `Crash: ${err.message}\n${err.stack || ''}` })
})

process.on('unhandledRejection', (reason) => {
  const msg = reason instanceof Error ? reason.message : String(reason)
  const stack = reason instanceof Error ? (reason.stack || '') : ''
  console.error('[unhandledRejection]', reason)
  send('scan-error', { message: `Unhandled rejection: ${msg}\n${stack}` })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow()
})

// ─── IPC Helpers ─────────────────────────────────────────────────────────────

function send(channel, data) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(channel, data)
  }
}

/**
 * Strip any Buffer / non-serializable values from an object before sending
 * over Electron IPC. Electron uses structured clone which rejects Buffers.
 */
function sanitize(obj) {
  if (obj === null || obj === undefined) return obj
  if (Buffer.isBuffer(obj)) return `<Buffer ${obj.length}b>`
  if (Array.isArray(obj)) return obj.map(sanitize)
  if (typeof obj === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === 'function') continue
      out[k] = sanitize(v)
    }
    return out
  }
  return obj
}

// ─── Network Interfaces ───────────────────────────────────────────────────────

ipcMain.handle('get-network-interfaces', () => {
  const ifaces = os.networkInterfaces()
  const results = [{ label: 'All interfaces (0.0.0.0)', address: '0.0.0.0', broadcast: '255.255.255.255' }]

  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        // Compute subnet broadcast address from IP and netmask
        const ipParts   = addr.address.split('.').map(Number)
        const maskParts = addr.netmask.split('.').map(Number)
        const broadcast = ipParts.map((octet, i) => (octet | (~maskParts[i] & 0xFF))).join('.')
        results.push({ label: `${name} — ${addr.address}`, address: addr.address, broadcast })
      }
    }
  }
  return results
})

// ─── Scan ─────────────────────────────────────────────────────────────────────

ipcMain.handle('start-scan', async (_event, bindAddress = '0.0.0.0', protocol = 'both', broadcastAddress = '255.255.255.255', subnetOverride = '') => {
  // Clean up any existing scanner.
  // removeAllListeners() is critical: it prevents the OLD async scan (which may
  // still have live timers / promises in flight) from sending stale scan-progress
  // events into the NEW scan's log after clearAll() has run in the renderer.
  if (scanner) { scanner.removeAllListeners(); scanner.stop(); scanner = null }

  // Build the list of broadcast addresses to poll.
  // If "All interfaces" is selected (0.0.0.0) enumerate every NIC's subnet broadcast
  // so that Art-Net nodes on any connected network are discovered.
  let broadcasts
  if (bindAddress === '0.0.0.0') {
    broadcasts = ['255.255.255.255']  // limited broadcast — reaches all NICs
    const ifaces = os.networkInterfaces()
    const has10 = false
    for (const addrs of Object.values(ifaces)) {
      for (const addr of addrs) {
        if (addr.family === 'IPv4' && !addr.internal) {
          const ipParts   = addr.address.split('.').map(Number)
          const maskParts = addr.netmask.split('.').map(Number)
          // Per-NIC subnet broadcast (e.g. 192.168.1.255 for a /24)
          const bc = ipParts.map((o, i) => (o | (~maskParts[i] & 0xFF))).join('.')
          if (!broadcasts.includes(bc)) broadcasts.push(bc)
          // Class-A wider broadcast for 10.x.x.x NICs — catches devices
          // configured with a /8 mask (e.g. Pathway Pathport nodes at 10.30.142.x
          // with 255.0.0.0) that only respond to 10.255.255.255 broadcasts
          if (ipParts[0] === 10 && !broadcasts.includes('10.255.255.255')) {
            broadcasts.push('10.255.255.255')
          }
          // Similarly for 172.16-31.x.x and 192.168.x.x wider broadcasts
          if (ipParts[0] === 172 && ipParts[1] >= 16 && ipParts[1] <= 31
              && !broadcasts.includes('172.31.255.255')) {
            broadcasts.push('172.31.255.255')
          }
          if (ipParts[0] === 192 && ipParts[1] === 168
              && !broadcasts.includes('192.168.255.255')) {
            broadcasts.push('192.168.255.255')
          }
        }
      }
    }
  } else {
    broadcasts = [broadcastAddress]
  }

  scanner = new Scanner()

  scanner.on('nodeFound',  (node)   => send('node-found',     sanitize(node)))
  scanner.on('deviceFound',(device) => send('device-found',   sanitize(device)))
  scanner.on('progress',   (data)   => send('scan-progress',  sanitize(data)))
  scanner.on('error',      (err)    => send('scan-error',     { message: err.message }))

  try {
    await scanner.start(bindAddress, protocol, broadcasts, subnetOverride)
    scanner.setManualNodes(manualNodes)
    const devices = await scanner.fullScan(bindAddress, null, protocol)
    send('scan-done', { deviceCount: devices.length })
    return { ok: true, deviceCount: devices.length }
  } catch (err) {
    send('scan-error', { message: err.message })
    return { ok: false, error: err.message }
  }
})

ipcMain.handle('stop-scan', () => {
  if (scanner) { scanner.stop(); scanner = null }
  return { ok: true }
})

// ─── Device Control ───────────────────────────────────────────────────────────

ipcMain.handle('set-dmx-address', async (_event, device, address) => {
  if (!scanner) return { ok: false, error: 'No active scanner' }
  try {
    await scanner.setDmxAddress(device, address)
    return { ok: true }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

ipcMain.handle('set-device-label', async (_event, device, label) => {
  if (!scanner) return { ok: false, error: 'No active scanner' }
  try {
    await scanner.setDeviceLabel(device, label)
    return { ok: true }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

ipcMain.handle('identify-device', async (_event, device, on) => {
  if (!scanner) return { ok: false, error: 'No active scanner' }
  try {
    await scanner.identifyDevice(device, on)
    return { ok: true }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

// ─── Manual Nodes ─────────────────────────────────────────────────────────────

ipcMain.handle('get-manual-nodes', () => manualNodes)

ipcMain.handle('add-manual-node', (_event, ip, name) => {
  // Validate basic IPv4 format
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return { ok: false, error: 'Invalid IP address' }
  if (manualNodes.find(n => n.ip === ip)) return { ok: false, error: 'Node already added' }
  // Default to 16 universes (0–15) on net 0, sub 0
  // Covers a full Pathport 8-port node plus offset configurations.
  // Users should check Pathscape to confirm the actual Art-Net universe mapping.
  const universes = Array.from({ length: 16 }, (_, i) => ({ net: 0, sub: 0, uni: i }))
  manualNodes.push({ ip, name: name || `Manual Node @ ${ip}`, universes })
  return { ok: true }
})

ipcMain.handle('remove-manual-node', (_event, ip) => {
  manualNodes = manualNodes.filter(n => n.ip !== ip)
  return { ok: true }
})

// ─── Update Checker ──────────────────────────────────────────────────────────

const GITHUB_OWNER = 'YoshiBowman'
const GITHUB_REPO  = 'rdm-explorer'

ipcMain.handle('check-for-updates', () => checkForUpdates())

function checkForUpdates() {
  const options = {
    hostname: 'api.github.com',
    path:     `/repos/${GITHUB_OWNER}/${GITHUB_REPO}/releases/latest`,
    headers:  { 'User-Agent': 'RDM-Explorer' },
    timeout:  8000,
  }

  return new Promise((resolve) => {
    const req = https.get(options, (res) => {
      let body = ''
      res.on('data', (chunk) => body += chunk)
      res.on('end', () => {
        try {
          const release = JSON.parse(body)
          const latest  = (release.tag_name || '').replace(/^v/, '')
          const current = app.getVersion()

          if (latest && latest !== current && _isNewer(latest, current)) {
            const info = {
              version:  latest,
              url:      release.html_url,
              notes:    release.body || '',
            }
            send('update-available', info)
            resolve(info)
          } else {
            resolve(null)
          }
        } catch (_) {
          resolve(null)
        }
      })
    })

    req.on('error', () => resolve(null))
    req.on('timeout', () => { req.destroy(); resolve(null) })
  })
}

/**
 * Simple semver comparison: returns true if `a` is newer than `b`.
 */
function _isNewer(a, b) {
  const pa = a.split('.').map(Number)
  const pb = b.split('.').map(Number)
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true
    if ((pa[i] || 0) < (pb[i] || 0)) return false
  }
  return false
}
