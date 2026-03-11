/**
 * main.js
 * Electron main process.
 * Creates the browser window, handles IPC, and drives the Scanner.
 */

'use strict'

const { app, BrowserWindow, ipcMain } = require('electron')
const path = require('path')
const os   = require('os')
const Scanner = require('./src/scanner')

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
    show: false, // show after ready-to-show
  })

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'))

  mainWindow.once('ready-to-show', () => mainWindow.show())

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

ipcMain.handle('start-scan', async (_event, bindAddress = '0.0.0.0') => {
  // Clean up any existing scanner
  if (scanner) { scanner.stop(); scanner = null }

  scanner = new Scanner()

  scanner.on('nodeFound',  (node)   => send('node-found',     node))
  scanner.on('deviceFound',(device) => send('device-found',   device))
  scanner.on('progress',   (data)   => send('scan-progress',  data))
  scanner.on('error',      (err)    => send('scan-error',     { message: err.message }))

  try {
    await scanner.start(bindAddress)
    const devices = await scanner.fullScan(bindAddress, null)
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
