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

let mainWindow = null
let scanner    = null

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

// ─── Network Interfaces ───────────────────────────────────────────────────────

ipcMain.handle('get-network-interfaces', () => {
  const ifaces = os.networkInterfaces()
  const results = [{ label: 'All interfaces (0.0.0.0)', address: '0.0.0.0' }]

  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        results.push({ label: `${name} — ${addr.address}`, address: addr.address })
      }
    }
  }
  return results
})

// ─── Scan ─────────────────────────────────────────────────────────────────────

ipcMain.handle('start-scan', async (_event, bindAddress = '0.0.0.0', protocol = 'both') => {
  // Clean up any existing scanner
  if (scanner) { scanner.stop(); scanner = null }

  scanner = new Scanner()

  scanner.on('nodeFound',  (node)   => send('node-found',     node))
  scanner.on('deviceFound',(device) => send('device-found',   device))
  scanner.on('progress',   (data)   => send('scan-progress',  data))
  scanner.on('error',      (err)    => send('scan-error',     { message: err.message }))

  try {
    await scanner.start(bindAddress, protocol)
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

// ─── Update Checker ──────────────────────────────────────────────────────────

ipcMain.handle('check-for-updates', () => checkForUpdates())

function checkForUpdates() {
  const options = {
    hostname: 'api.github.com',
    path:     `/repos/${PKG.build.publish.owner}/${PKG.build.publish.repo}/releases/latest`,
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
          const current = PKG.version

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
