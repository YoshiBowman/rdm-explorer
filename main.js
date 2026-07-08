/**
 * main.js
 * Electron main process.
 * Creates the browser window, handles IPC, drives the Scanner, and checks for updates.
 */

'use strict'

const { app, BrowserWindow, ipcMain, shell } = require('electron')
const path  = require('path')
const os    = require('os')
const https = require('https')
const { autoUpdater } = require('electron-updater')
const Scanner    = require('./src/scanner')
const ScanLogger = require('./src/logger')

const PKG     = require('./package.json')

// Scan logs directory.
// Packaged builds MUST NOT use __dirname — it points inside the read-only
// app.asar bundle, and mkdir there throws ENOTDIR, killing every scan before it
// starts. Use the per-user data dir instead (~/Library/Application Support/…).
// Dev keeps ./logs in the project folder for convenience.
const LOGS_DIR = app.isPackaged
  ? path.join(app.getPath('userData'), 'logs')
  : path.join(__dirname, 'logs')

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
    // Check for updates a few seconds after launch.
    // Packaged builds use electron-updater (can download + install in place);
    // running from source falls back to the lightweight GitHub API check.
    setTimeout(() => { app.isPackaged ? checkForUpdatesAuto() : checkForUpdates() }, 4000)
  })

  mainWindow.on('closed', () => {
    mainWindow = null
    if (scanner) { scanner.destroy(); scanner = null }
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

ipcMain.handle('get-app-version', () => app.getVersion())

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

  // ── Start scan logger ────────────────────────────────────────────────────
  // Logging is auxiliary: if it can't start (permissions, disk, path), warn and
  // scan anyway with a no-op logger — a log failure must never block scanning.
  let logger = new ScanLogger(LOGS_DIR, {
    appVersion:     PKG.version,
    bindAddress,
    protocol,
    broadcasts,
    subnetOverride,
    manualNodes,
  })
  try {
    logger.open()
  } catch (e) {
    console.error('[logger] failed to open scan log:', e.message)
    const noop = () => {}
    logger = { nodeFound: noop, deviceFound: noop, progress: noop, error: noop,
               close: noop, filePath: null }
    send('scan-progress', { message: `⚠ Scan log disabled (${e.message}) — scanning continues` })
  }

  scanner = new Scanner()

  scanner.on('nodeFound',   (node)   => { logger.nodeFound(node);         send('node-found',    sanitize(node))   })
  scanner.on('deviceFound', (device) => { logger.deviceFound(device);     send('device-found',  sanitize(device)) })
  scanner.on('progress',    (data)   => { logger.progress(data);          send('scan-progress', sanitize(data))   })
  scanner.on('error',       (err)    => { logger.error(err);              send('scan-error',    { message: err.message }) })

  // Also log crashes that arrive via uncaughtException (they re-fire the scan-error channel)
  const crashLogger = (err) => logger.error(`[crash] ${err.message || err}\n${err.stack || ''}`)
  process.once('uncaughtException',  crashLogger)
  process.once('unhandledRejection', crashLogger)

  try {
    await scanner.start(bindAddress, protocol, broadcasts, subnetOverride)
    scanner.setManualNodes(manualNodes)
    const devices = await scanner.fullScan(bindAddress, null, protocol)
    logger.close({ deviceCount: devices.length })
    process.removeListener('uncaughtException',  crashLogger)
    process.removeListener('unhandledRejection', crashLogger)
    send('scan-done', { deviceCount: devices.length, logPath: logger.filePath })
    return { ok: true, deviceCount: devices.length, logPath: logger.filePath }
  } catch (err) {
    logger.error(err)
    logger.close({ deviceCount: 0, error: err.message })
    process.removeListener('uncaughtException',  crashLogger)
    process.removeListener('unhandledRejection', crashLogger)
    send('scan-error', { message: err.message })
    return { ok: false, error: err.message }
  }
})

ipcMain.handle('stop-scan', () => {
  if (scanner) { scanner.removeAllListeners(); scanner.stop(); scanner = null }
  return { ok: true }
})

// ─── Device Control ───────────────────────────────────────────────────────────

// Shared wrapper: run a device SET and translate the RDM response into
// { ok, error } — a NACK (write-protect, out-of-range, …) is a REAL failure
// with the fixture's stated reason, not a silent fake success.
async function handleDeviceSet(fn) {
  if (!scanner) return { ok: false, error: 'No active scanner' }
  try {
    const resp = await fn()
    return Scanner.setResult(resp)
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

ipcMain.handle('set-dmx-address', (_event, device, address) =>
  handleDeviceSet(() => scanner.setDmxAddress(device, address)))

ipcMain.handle('set-device-label', (_event, device, label) =>
  handleDeviceSet(() => scanner.setDeviceLabel(device, label)))

ipcMain.handle('identify-device', (_event, device, on) =>
  handleDeviceSet(() => scanner.identifyDevice(device, on)))

ipcMain.handle('set-device-personality', (_event, device, personality) =>
  handleDeviceSet(() => scanner.setDevicePersonality(device, personality)))

// One-time detail fetch when the fixture panel opens (personalities + sensor defs)
ipcMain.handle('get-device-detail', async (_event, device) => {
  if (!scanner) return { ok: false, error: 'No active scanner' }
  try {
    const detail = await scanner.getDeviceDetail(device)
    return { ok: true, detail: sanitize(detail) }
  } catch (e) {
    return { ok: false, error: e.message }
  }
})

// Repeated poll while the fixture panel is open (sensor values, vitals, status)
ipcMain.handle('poll-device-vitals', async (_event, device, sensorNums) => {
  if (!scanner) return { ok: false, error: 'No active scanner' }
  try {
    const vitals = await scanner.pollDeviceVitals(device, sensorNums || [])
    return { ok: true, vitals: sanitize(vitals) }
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

// ─── Logs ─────────────────────────────────────────────────────────────────────

/** Open the logs folder in the OS file manager. */
ipcMain.handle('open-logs-folder', () => {
  const fs = require('fs')
  if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true })
  shell.openPath(LOGS_DIR)
  return { ok: true, path: LOGS_DIR }
})

/** Return a list of scan log files, newest first. */
ipcMain.handle('list-log-files', () => {
  const fs = require('fs')
  if (!fs.existsSync(LOGS_DIR)) return []
  return fs.readdirSync(LOGS_DIR)
    .filter(f => f.startsWith('scan-') && f.endsWith('.log'))
    .map(f => {
      const full = require('path').join(LOGS_DIR, f)
      const stat = fs.statSync(full)
      return { name: f, path: full, sizeBytes: stat.size, mtimeMs: stat.mtimeMs }
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs)
})

/** Read the most recent log file and return its contents as a string. */
ipcMain.handle('read-latest-log', () => {
  const fs = require('fs')
  if (!fs.existsSync(LOGS_DIR)) return null
  const files = fs.readdirSync(LOGS_DIR)
    .filter(f => f.startsWith('scan-') && f.endsWith('.log'))
    .map(f => ({ name: f, mtime: fs.statSync(require('path').join(LOGS_DIR, f)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)
  if (files.length === 0) return null
  const latest = require('path').join(LOGS_DIR, files[0].name)
  return { name: files[0].name, content: fs.readFileSync(latest, 'utf8') }
})

// ─── Update Checker ──────────────────────────────────────────────────────────

const GITHUB_OWNER = 'YoshiBowman'
const GITHUB_REPO  = 'rdm-explorer'

// ── electron-updater (packaged builds) ────────────────────────────────────────
// Downloads the update in the background and installs it on quit/restart.
// Reads the publish config baked in at build time (GitHub releases), so it needs
// the release to carry electron-builder's latest*.yml metadata (the CI publishes it).
let _updateDownloaded = false

autoUpdater.autoDownload = true
autoUpdater.autoInstallOnAppQuit = true
autoUpdater.on('update-available', (info) => {
  send('update-available', { version: info.version, notes: releaseNotesToText(info.releaseNotes), downloading: true })
})
autoUpdater.on('download-progress', (p) => {
  send('update-progress', { percent: Math.round(p.percent) })
})
autoUpdater.on('update-downloaded', (info) => {
  _updateDownloaded = true
  send('update-downloaded', { version: info.version })
})
autoUpdater.on('error', (err) => {
  // Non-fatal: log and let the UI stay quiet. A failed auto-check should never
  // interrupt the user; they can still download manually from the releases page.
  console.error('[autoUpdater]', err && err.message ? err.message : err)
})

function checkForUpdatesAuto() {
  try { autoUpdater.checkForUpdates() } catch (e) { console.error('[autoUpdater] check failed', e.message) }
}

// electron-updater releaseNotes can be a string or an array of {version,note}
function releaseNotesToText(notes) {
  if (!notes) return ''
  if (typeof notes === 'string') return notes
  if (Array.isArray(notes)) return notes.map(n => n.note || '').join('\n\n')
  return ''
}

// Renderer asks to restart & install the downloaded update
ipcMain.handle('install-update', () => {
  if (_updateDownloaded) {
    setImmediate(() => autoUpdater.quitAndInstall())
    return { ok: true }
  }
  return { ok: false, error: 'No update downloaded yet' }
})

ipcMain.handle('check-for-updates', () => (app.isPackaged ? checkForUpdatesAuto() : checkForUpdates()))

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
