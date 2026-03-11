/**
 * scanner.js
 * Orchestrates Art-Net node discovery and RDM device enumeration.
 * Emits events: nodeFound, deviceFound, progress, error
 */

'use strict'

const EventEmitter = require('events')
const ArtNet = require('./artnet')
const RDM    = require('./rdm')

const POLL_WAIT_MS   = 2500   // Wait after ArtPoll for replies
const RDM_TIMEOUT_MS = 400    // Timeout waiting for a single RDM response
const RDM_SET_TIMEOUT_MS = 600

class Scanner extends EventEmitter {
  constructor() {
    super()
    this.artnet = new ArtNet()
    this.nodes  = new Map()    // ip → node info
    this._pendingCallback = null  // one active response callback at a time
    this.running = false
  }

  async start(bindAddress = '0.0.0.0') {
    await this.artnet.start(bindAddress)

    this.artnet.on('artPollReply', (node) => {
      if (node) {
        const isNew = !this.nodes.has(node.ip)
        this.nodes.set(node.ip, node)
        if (isNew) this.emit('nodeFound', node)
      }
    })

    this.artnet.on('artRdmData', (data, rinfo) => {
      if (this._pendingCallback) {
        const cb = this._pendingCallback
        this._pendingCallback = null
        cb(data, rinfo)
      }
    })

    this.artnet.on('error', (err) => this.emit('error', err))
  }

  stop() {
    this.artnet.stop()
    this.running = false
  }

  // ─── Art-Net Node Discovery ─────────────────────────────────────────────────

  async discoverNodes() {
    this.nodes.clear()
    this.artnet.sendArtPoll()
    // Re-poll after a short gap to catch slower nodes
    await this._delay(800)
    this.artnet.sendArtPoll()
    await this._delay(POLL_WAIT_MS - 800)
    return Array.from(this.nodes.values())
  }

  // ─── RDM Send / Receive ─────────────────────────────────────────────────────

  /**
   * Send an RDM packet and wait for a response from the given node.
   * Returns the raw RDM buffer, or null on timeout.
   */
  async _sendAndReceive(nodeIP, net, sub, uni, packet, timeout = RDM_TIMEOUT_MS) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this._pendingCallback = null
        resolve(null)
      }, timeout)

      this._pendingCallback = (data, rinfo) => {
        if (rinfo.address === nodeIP) {
          clearTimeout(timer)
          resolve(data)
        } else {
          // Not our node — put callback back and let the next packet hit it
          this._pendingCallback = (d2, r2) => {
            if (r2.address === nodeIP) { clearTimeout(timer); resolve(d2) }
          }
        }
      }

      this.artnet.sendArtRdm(nodeIP, net, sub, uni, packet)
    })
  }

  // ─── RDM Discovery (Binary Tree) ────────────────────────────────────────────

  async discoverRDMDevices(nodeIP, net, sub, uni) {
    const found = new Map() // uid string → uid buffer

    // Un-mute all devices first
    const unMuteAll = RDM.buildDiscUnMuteAll()
    await this._sendAndReceive(nodeIP, net, sub, uni, unMuteAll, 200)
    await this._delay(80)

    const lower = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    const upper = Buffer.from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

    await this._discoveryBranch(nodeIP, net, sub, uni, lower, upper, found, 0)
    return Array.from(found.entries()).map(([uidStr, uidBuf]) => ({ uidStr, uidBuf }))
  }

  async _discoveryBranch(nodeIP, net, sub, uni, lower, upper, found, depth) {
    if (depth > 50) return  // Hard cap to prevent runaway recursion

    const dub      = RDM.buildDiscUniqueBranch(lower, upper)
    const response = await this._sendAndReceive(nodeIP, net, sub, uni, dub, RDM_TIMEOUT_MS)

    if (!response) return // No devices in this range

    // Attempt to decode as a discovery response
    const uid = RDM.parseDiscoveryResponse(response)

    if (uid) {
      const uidStr = RDM.uidToString(uid)
      if (!found.has(uidStr)) {
        // Mute this device so it stays quiet while we find others
        const mute = RDM.buildDiscMute(uid)
        await this._sendAndReceive(nodeIP, net, sub, uni, mute, 300)
        found.set(uidStr, uid)
        this.emit('uidFound', { uidStr, nodeIP })
      }
      // Continue searching the same range — more devices might be hiding
      await this._discoveryBranch(nodeIP, net, sub, uni, lower, upper, found, depth + 1)
    } else {
      // Collision or garbled response — split the range and recurse both halves
      const mid = this._midUID(lower, upper)
      if (!mid) return

      await this._discoveryBranch(nodeIP, net, sub, uni, lower, mid, found, depth + 1)

      const midPlus = this._incrementUID(mid)
      if (midPlus) {
        await this._discoveryBranch(nodeIP, net, sub, uni, midPlus, upper, found, depth + 1)
      }
    }
  }

  // ─── RDM GET / SET ──────────────────────────────────────────────────────────

  async getRDMParam(nodeIP, net, sub, uni, uid, pid, pd = null) {
    const uidBuf  = typeof uid === 'string' ? RDM.stringToUID(uid) : uid
    const request = RDM.buildGetRequest(uidBuf, pid, pd)
    const raw     = await this._sendAndReceive(nodeIP, net, sub, uni, request, RDM_TIMEOUT_MS)
    if (!raw) return null
    return RDM.parsePacket(raw)
  }

  async setRDMParam(nodeIP, net, sub, uni, uid, pid, pd) {
    const uidBuf  = typeof uid === 'string' ? RDM.stringToUID(uid) : uid
    const request = RDM.buildSetRequest(uidBuf, pid, pd)
    const raw     = await this._sendAndReceive(nodeIP, net, sub, uni, request, RDM_SET_TIMEOUT_MS)
    if (!raw) return null
    return RDM.parsePacket(raw)
  }

  // ─── Full Device Info ────────────────────────────────────────────────────────

  async getDeviceInfo(nodeIP, net, sub, uni, uidStr, uidBuf) {
    const info = { uid: uidStr, nodeIP, net, sub, uni }

    // DEVICE_INFO
    const diResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.DEVICE_INFO)
    if (diResp && diResp.pd) {
      Object.assign(info, RDM.parseDeviceInfo(diResp.pd))
    }

    // MANUFACTURER_LABEL
    const mfgResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.MANUFACTURER_LABEL)
    if (mfgResp?.pd) info.manufacturerLabel = _parseStr(mfgResp.pd)

    // DEVICE_MODEL_DESCRIPTION
    const modelResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.DEVICE_MODEL_DESCRIPTION)
    if (modelResp?.pd) info.deviceModelDescription = _parseStr(modelResp.pd)

    // DEVICE_LABEL
    const labelResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.DEVICE_LABEL)
    if (labelResp?.pd) info.deviceLabel = _parseStr(labelResp.pd)

    // SOFTWARE_VERSION_LABEL
    const swResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.SOFTWARE_VERSION_LABEL)
    if (swResp?.pd) info.softwareVersionLabel = _parseStr(swResp.pd)

    // DMX_PERSONALITY_DESCRIPTION for the current personality
    if (info.currentPersonality > 0) {
      const pPD = Buffer.alloc(1)
      pPD[0] = info.currentPersonality
      const persResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.DMX_PERSONALITY_DESCRIPTION, pPD)
      if (persResp?.pd && persResp.pd.length >= 3) {
        info.personalityName     = _parseStr(persResp.pd.slice(2))
        info.personalityFootprint = persResp.pd.readUInt16BE(0)
      }
    }

    return info
  }

  // ─── Convenience Actions ────────────────────────────────────────────────────

  async setDmxAddress(device, newAddress) {
    const { nodeIP, net, sub, uni, uid } = device
    const pd = Buffer.alloc(2)
    pd.writeUInt16BE(newAddress, 0)
    return this.setRDMParam(nodeIP, net, sub, uni, uid, RDM.PID.DMX_START_ADDRESS, pd)
  }

  async setDeviceLabel(device, label) {
    const { nodeIP, net, sub, uni, uid } = device
    const pd = Buffer.from(label.slice(0, 32), 'ascii')
    return this.setRDMParam(nodeIP, net, sub, uni, uid, RDM.PID.DEVICE_LABEL, pd)
  }

  async identifyDevice(device, on) {
    const { nodeIP, net, sub, uni, uid } = device
    const pd = Buffer.alloc(1)
    pd[0] = on ? 0x01 : 0x00
    return this.setRDMParam(nodeIP, net, sub, uni, uid, RDM.PID.IDENTIFY_DEVICE, pd)
  }

  // ─── Full Scan Workflow ─────────────────────────────────────────────────────

  async fullScan(bindAddress, onProgress) {
    this.running = true
    const report = (msg, extra = {}) => {
      this.emit('progress', { message: msg, ...extra })
      if (onProgress) onProgress({ message: msg, ...extra })
    }

    try {
      report('Searching for Art-Net nodes on the network…')
      const nodes = await this.discoverNodes()

      if (nodes.length === 0) {
        report('No Art-Net nodes found. Check network connection and node power.')
        return []
      }

      report(`Found ${nodes.length} node(s). Starting RDM discovery…`, { nodes })

      const allDevices = []

      for (const node of nodes) {
        report(`Scanning node: ${node.shortName} (${node.ip})`)

        if (!node.supportsRDM) {
          report(`  ${node.shortName} does not appear to support RDM — skipping RDM scan.`)
        }

        const universesToScan = node.universes.length > 0
          ? node.universes
          : [{ net: 0, sub: 0, uni: 0 }]

        for (const uniInfo of universesToScan) {
          const uniLabel = `${uniInfo.net}.${uniInfo.sub}.${uniInfo.uni}`
          report(`  Discovering RDM devices on universe ${uniLabel}…`)

          let uids = []
          try {
            uids = await this.discoverRDMDevices(node.ip, uniInfo.net, uniInfo.sub, uniInfo.uni)
          } catch (e) {
            report(`  Error on universe ${uniLabel}: ${e.message}`)
            continue
          }

          if (uids.length === 0) {
            report(`  No RDM devices found on universe ${uniLabel}.`)
            continue
          }

          report(`  Found ${uids.length} RDM UID(s) on universe ${uniLabel}. Reading device info…`)

          for (const { uidStr, uidBuf } of uids) {
            report(`    Reading: ${uidStr}`)
            try {
              const deviceInfo = await this.getDeviceInfo(
                node.ip, uniInfo.net, uniInfo.sub, uniInfo.uni, uidStr, uidBuf
              )
              deviceInfo.universe    = uniLabel
              deviceInfo.nodeName    = node.shortName
              deviceInfo.nodeIP      = node.ip
              allDevices.push(deviceInfo)
              this.emit('deviceFound', deviceInfo)
            } catch (e) {
              report(`    Error reading ${uidStr}: ${e.message}`)
            }
          }
        }
      }

      report(`Scan complete — ${allDevices.length} device(s) found.`, { done: true })
      return allDevices

    } finally {
      this.running = false
    }
  }

  // ─── UID Math ────────────────────────────────────────────────────────────────

  _midUID(lower, upper) {
    const lo = BigInt('0x' + lower.toString('hex'))
    const hi = BigInt('0x' + upper.toString('hex'))
    if (lo >= hi) return null
    const mid = (lo + hi) / 2n
    return Buffer.from(mid.toString(16).padStart(12, '0'), 'hex')
  }

  _incrementUID(uid) {
    const val = BigInt('0x' + uid.toString('hex')) + 1n
    if (val > 0xFFFFFFFFFFFFn) return null
    return Buffer.from(val.toString(16).padStart(12, '0'), 'hex')
  }

  _delay(ms) {
    return new Promise(r => setTimeout(r, ms))
  }
}

function _parseStr(buf) {
  return buf.toString('ascii').replace(/\0/g, '').trim()
}

module.exports = Scanner
