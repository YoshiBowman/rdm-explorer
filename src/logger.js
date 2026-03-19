/**
 * logger.js
 * Per-scan log file writer.
 *
 * Creates one timestamped log file per scan in <appDir>/logs/.
 * Captures every event emitted during a scan:
 *   - Full scan progress messages (the same text shown in the UI log)
 *   - Every node discovered (JSON)
 *   - Every RDM device discovered (JSON)
 *   - Any errors
 *   - Scan metadata: app version, OS, interfaces, bind address, protocol,
 *                    broadcast targets, manual nodes, start/end time, duration
 *
 * Log retention: keeps the 25 most recent scan logs, deletes older ones.
 */

'use strict'

const fs   = require('fs')
const path = require('path')
const os   = require('os')

const MAX_LOGS = 25

class ScanLogger {
  /**
   * @param {string} logsDir   - Absolute path to the logs/ folder
   * @param {object} meta      - Scan metadata to write into the file header
   *   meta.appVersion   {string}
   *   meta.bindAddress  {string}
   *   meta.protocol     {string}  'artnet' | 'sacn' | 'both'
   *   meta.broadcasts   {string[]}
   *   meta.subnetOverride {string}
   *   meta.manualNodes  {object[]}
   */
  constructor(logsDir, meta = {}) {
    this.logsDir   = logsDir
    this.meta      = meta
    this.filePath  = null
    this.stream    = null
    this.startTime = null

    // Counters for the summary footer
    this._nodes   = []
    this._devices = []
    this._errors  = []
  }

  // ─── Lifecycle ────────────────────────────────────────────────────────────

  open() {
    // Ensure logs directory exists
    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true })
    }

    this.startTime = new Date()

    // Filename: scan-YYYY-MM-DD_HH-MM-SS.log
    const ts = this.startTime.toISOString()
      .replace('T', '_')
      .replace(/:/g, '-')
      .slice(0, 19)
    this.filePath = path.join(this.logsDir, `scan-${ts}.log`)

    this.stream = fs.createWriteStream(this.filePath, { encoding: 'utf8', flags: 'w' })

    this._writeHeader()
  }

  close(summary = {}) {
    if (!this.stream) return
    this._writeFooter(summary)
    this.stream.end()
    this.stream = null

    // Prune old log files (keep MAX_LOGS most recent)
    this._pruneOldLogs()
  }

  // ─── Event Writers ────────────────────────────────────────────────────────

  /** Write a scan progress message (same text as the UI log). */
  progress(data) {
    const msg = (typeof data === 'string') ? data : (data.message || '')
    this._writeLine('SCAN', msg)
  }

  /** Write a discovered node (Art-Net, sACN, or passive). */
  nodeFound(node) {
    this._nodes.push(node)
    this._writeLine('NODE', JSON.stringify({
      ip:          node.ip,
      protocol:    node.protocol,
      shortName:   node.shortName,
      longName:    node.longName,
      supportsRDM: node.supportsRDM,
      universes:   node.universes ? node.universes.length : 0,
      universeList: node.universes,
      priority:    node.priority,
      firmwareVer: node.firmwareVer,
      mac:         node.mac,
    }))
  }

  /** Write a discovered RDM device. */
  deviceFound(device) {
    this._devices.push(device)
    this._writeLine('DEVICE', JSON.stringify({
      uid:          device.uid || device.uidStr,
      label:        device.label || device.deviceLabel,
      manufacturer: device.manufacturer || device.manufacturerLabel,
      model:        device.model        || device.modelDescription,
      category:     device.category     || device.productCategory,
      dmxAddress:   device.dmxAddress   || device.dmxStartAddress,
      footprint:    device.footprint     || device.dmxFootprint,
      universe:     device.universe,
      nodeName:     device.nodeName,
      nodeIP:       device.nodeIP,
      protocol:     device.protocol,
      transport:    device.transport,
      firmwareVer:  device.firmwareVersion,
    }))
  }

  /** Write an error. */
  error(err) {
    const msg = (err instanceof Error) ? `${err.message}\n${err.stack || ''}` : String(err)
    this._errors.push(msg)
    this._writeLine('ERROR', msg)
  }

  // ─── Internal Helpers ─────────────────────────────────────────────────────

  _writeLine(tag, text) {
    if (!this.stream) return
    const ts  = new Date().toISOString().slice(11, 23)  // HH:MM:SS.mmm
    const lines = text.split('\n')
    for (let i = 0; i < lines.length; i++) {
      const prefix = i === 0 ? `[${ts}] [${tag.padEnd(6)}] ` : `                    ` // align continuation lines
      this.stream.write(prefix + lines[i] + '\n')
    }
  }

  _writeHeader() {
    const m   = this.meta
    const sep = '═'.repeat(72)

    const header = [
      sep,
      `RDM EXPLORER — SCAN LOG`,
      sep,
      `Date/Time   : ${this.startTime.toLocaleString()}`,
      `App Version : ${m.appVersion || 'unknown'}`,
      `OS          : ${os.type()} ${os.release()} (${os.arch()})`,
      `Hostname    : ${os.hostname()}`,
      ``,
      `SCAN CONFIGURATION`,
      `─`.repeat(40),
      `Bind Address: ${m.bindAddress || '0.0.0.0'}`,
      `Protocol    : ${m.protocol   || 'both'}`,
      `Broadcasts  : ${(m.broadcasts || []).join(', ') || '(none)'}`,
      `Subnet Sweep: ${m.subnetOverride || '(none)'}`,
      ``,
      `MANUAL NODES (${(m.manualNodes || []).length})`,
      `─`.repeat(40),
    ]

    if (m.manualNodes && m.manualNodes.length > 0) {
      for (const mn of m.manualNodes) {
        header.push(`  ${mn.ip.padEnd(18)} ${mn.name || ''}`)
      }
    } else {
      header.push('  (none)')
    }

    header.push('')
    header.push('NETWORK INTERFACES')
    header.push('─'.repeat(40))
    const ifaces = os.networkInterfaces()
    for (const [name, addrs] of Object.entries(ifaces)) {
      for (const a of addrs) {
        if (a.family === 'IPv4') {
          header.push(`  ${name.padEnd(16)} ${a.address.padEnd(16)} ${a.internal ? '(loopback)' : `mask: ${a.netmask}`}`)
        }
      }
    }

    header.push('')
    header.push('SCAN EVENTS')
    header.push('─'.repeat(40))
    header.push('')

    for (const line of header) {
      this.stream.write(line + '\n')
    }
  }

  _writeFooter(summary = {}) {
    const endTime  = new Date()
    const elapsed  = ((endTime - this.startTime) / 1000).toFixed(1)
    const sep      = '═'.repeat(72)

    const footer = [
      '',
      '─'.repeat(40),
      'SCAN SUMMARY',
      '─'.repeat(40),
      `End Time    : ${endTime.toLocaleString()}`,
      `Duration    : ${elapsed}s`,
      `Nodes Found : ${this._nodes.length}`,
      `Devices Found: ${this._devices.length}`,
      `Errors       : ${this._errors.length}`,
      '',
    ]

    if (this._nodes.length > 0) {
      footer.push('NODES:')
      for (const n of this._nodes) {
        const proto = (n.protocol || 'unknown').padEnd(16)
        const rdm   = n.supportsRDM === true  ? 'RDM ✓'
                    : n.supportsRDM === false ? 'No RDM'
                    : 'RDM unknown'
        footer.push(`  ${(n.ip || '').padEnd(18)} [${proto}] ${n.shortName || ''} — ${rdm}`)
      }
      footer.push('')
    }

    if (this._devices.length > 0) {
      footer.push('RDM DEVICES:')
      for (const d of this._devices) {
        const uid  = (d.uid || d.uidStr || '').padEnd(14)
        const addr = d.dmxAddress != null ? `@ ${d.dmxAddress}`.padEnd(8) : '         '
        const name = d.label || d.deviceLabel || d.model || d.modelDescription || ''
        const mfr  = d.manufacturer || d.manufacturerLabel || ''
        footer.push(`  ${uid} ${addr} ${mfr} — ${name}  [${d.nodeIP || ''}]`)
      }
      footer.push('')
    }

    if (this._errors.length > 0) {
      footer.push('ERRORS:')
      for (const e of this._errors) {
        footer.push(`  ${e}`)
      }
      footer.push('')
    }

    footer.push(sep)
    footer.push(`Log file: ${this.filePath}`)
    footer.push(sep)

    for (const line of footer) {
      this.stream.write(line + '\n')
    }
  }

  _pruneOldLogs() {
    try {
      const files = fs.readdirSync(this.logsDir)
        .filter(f => f.startsWith('scan-') && f.endsWith('.log'))
        .map(f => ({ name: f, mtime: fs.statSync(path.join(this.logsDir, f)).mtimeMs }))
        .sort((a, b) => b.mtime - a.mtime)  // newest first

      const toDelete = files.slice(MAX_LOGS)
      for (const f of toDelete) {
        fs.unlinkSync(path.join(this.logsDir, f.name))
      }
    } catch (_) {
      // Non-fatal — if pruning fails, just leave the old logs in place
    }
  }
}

module.exports = ScanLogger
