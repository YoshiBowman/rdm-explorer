/**
 * preload.js
 * Exposes a safe, sandboxed API surface to the renderer via contextBridge.
 * The renderer never gets direct access to Node.js — only these functions.
 */

'use strict'

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('rdm', {
  // ── Discovery & Scanning ────────────────────────────────────────────────────
  getNetworkInterfaces: ()                        => ipcRenderer.invoke('get-network-interfaces'),
  startScan:            (bindAddress, protocol, broadcastAddress, subnetOverride) => ipcRenderer.invoke('start-scan', bindAddress, protocol, broadcastAddress, subnetOverride),
  stopScan:             ()                         => ipcRenderer.invoke('stop-scan'),

  // ── Manual Nodes ────────────────────────────────────────────────────────────
  getManualNodes:   ()          => ipcRenderer.invoke('get-manual-nodes'),
  addManualNode:    (ip, name)  => ipcRenderer.invoke('add-manual-node', ip, name),
  removeManualNode: (ip)        => ipcRenderer.invoke('remove-manual-node', ip),

  // ── Device Control ──────────────────────────────────────────────────────────
  setDmxAddress:  (device, address) => ipcRenderer.invoke('set-dmx-address', device, address),
  setDeviceLabel: (device, label)   => ipcRenderer.invoke('set-device-label', device, label),
  identifyDevice: (device, on)      => ipcRenderer.invoke('identify-device', device, on),

  // ── Updates ─────────────────────────────────────────────────────────────────
  checkForUpdates: () => ipcRenderer.invoke('check-for-updates'),

  // ── Events (main → renderer) ─────────────────────────────────────────────
  onProgress:       (cb) => ipcRenderer.on('scan-progress',     (_, d) => cb(d)),
  onNodeFound:      (cb) => ipcRenderer.on('node-found',        (_, d) => cb(d)),
  onDeviceFound:    (cb) => ipcRenderer.on('device-found',      (_, d) => cb(d)),
  onScanDone:       (cb) => ipcRenderer.on('scan-done',         (_, d) => cb(d)),
  onError:          (cb) => ipcRenderer.on('scan-error',        (_, d) => cb(d)),
  onUpdateAvailable:(cb) => ipcRenderer.on('update-available',  (_, d) => cb(d)),

  // ── Cleanup ─────────────────────────────────────────────────────────────────
  removeAllListeners: () => {
    ['scan-progress', 'node-found', 'device-found', 'scan-done', 'scan-error', 'update-available']
      .forEach(ch => ipcRenderer.removeAllListeners(ch))
  }
})
