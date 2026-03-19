/**
 * scanner.js
 * Orchestrates Art-Net node discovery, sACN source discovery, and RDM device enumeration.
 * Emits events: nodeFound, deviceFound, progress, error
 */

'use strict'

const EventEmitter = require('events')
const { exec }     = require('child_process')
const os       = require('os')
const ArtNet   = require('./artnet')
const SACN     = require('./sacn')
const RDM      = require('./rdm')
const RDMnet        = require('./rdmnet')
const RDMnetBroker  = require('./rdmnet-broker')

const POLL_WAIT_MS       = 2500   // Wait after ArtPoll for replies
const SACN_LISTEN_MS     = 3000   // Time to listen for sACN sources
const RDM_TIMEOUT_MS     = 400    // Timeout waiting for a single RDM response
const RDM_SET_TIMEOUT_MS = 600

// ── Embedded RDMnet Broker — module-level singleton ───────────────────────────
// Created once when this module first loads and reused across every Scanner
// instance (i.e. across every scan).  A new Scanner is created for each scan
// (main.js calls scanner.stop(); scanner = null on re-scan), but we must NOT
// recreate the broker each time or the new instance will hit EADDRINUSE because
// the previous broker is still listening on port 5569.
// destroy() is the ONLY path that shuts the broker down (called on app quit).
let _sharedBroker = new RDMnetBroker()
_sharedBroker.start().catch(() => {
  // Failure is non-fatal — logged in the Scanner constructor below where we
  // have access to this.emit().  We swallow here just to avoid an unhandled
  // rejection at module load time.
})

class Scanner extends EventEmitter {
  constructor() {
    super()
    this.artnet  = new ArtNet()
    this.sacn    = new SACN()
    this.rdmnet  = new RDMnet()
    this.nodes  = new Map()        // ip → node info (Art-Net)
    this.sacnSources = new Map()   // cid → source info (sACN)
    this.dmxSources  = new Map()   // ip → passive ArtDmx source info
    this.manualNodes = new Map()   // ip → manually added node info
    this._pendingCallback = null
    this._todCollector    = null   // active TOD collection callback (set during requestTOD)
    this.running = false

    // ── Embedded RDMnet Broker ─────────────────────────────────────────────
    // Re-use the module-level singleton so the TCP server never restarts
    // between scans (avoids EADDRINUSE on port 5569).
    this.broker = _sharedBroker

    // Forward broker log events as progress so they appear in scan logs.
    // removeAllListeners('log') first so we don't stack up handlers across
    // Scanner instances (a new Scanner is created on every scan).
    this.broker.removeAllListeners('log')
    this.broker.on('log', (msg) => this.emit('progress', { message: msg }))

    if (!this.broker.running) {
      // Previous start() failed (e.g. port conflict).  Try again — maybe the
      // conflicting process is gone now.
      this.broker.start().catch((err) => {
        this.emit('progress', { message: `[RDMnet Broker] Could not start on port 5569: ${err.message}. RDMnet gateway path unavailable.` })
      })
    }
  }

  /**
   * Start the scanner on the given bind address.
   * @param {string}          bindAddress    - Local IP to bind on (informational only; socket binds 0.0.0.0)
   * @param {string}          protocol       - 'artnet', 'sacn', or 'both'
   * @param {string|string[]} broadcasts     - One or more subnet broadcast addresses for ArtPoll
   * @param {string}          subnetOverride - Optional prefix like "10.30.142" for unicast sweep
   */
  async start(bindAddress = '0.0.0.0', protocol = 'both', broadcasts = ['255.255.255.255'], subnetOverride = '') {
    // Normalise to array and deduplicate
    this.broadcasts = [...new Set(Array.isArray(broadcasts) ? broadcasts : [broadcasts])]
    // Store subnet override for unicast sweep (e.g. "10.30.142")
    this.subnetOverride = (subnetOverride || '').trim().replace(/\.$/, '')
    const startArtNet = protocol === 'artnet' || protocol === 'both'
    const startSACN   = protocol === 'sacn'   || protocol === 'both'

    if (startArtNet) {
      await this.artnet.start()

      this.artnet.on('artPollReply', (node) => {
        if (node) {
          node.protocol = 'artnet'
          const isNew = !this.nodes.has(node.ip)
          this.nodes.set(node.ip, node)
          if (isNew) this.emit('nodeFound', node)
        }
      })

      this.artnet.on('artRdmData', (data, rinfo) => {
        // Don't null the callback here — let the callback itself decide.
        // This prevents losing the callback when unrelated ArtRdm packets
        // arrive from other nodes between request and response.
        if (this._pendingCallback) {
          this._pendingCallback(data, rinfo)
        }
      })

      // Passive ArtDmx source detection — track any device sending ArtDmx
      this.artnet.on('artDmx', (dmxInfo) => {
        if (!dmxInfo) return
        this._registerDmxSource(dmxInfo)
      })

      // ArtTodData — incoming TOD responses from proxy nodes (e.g. Pathport).
      // We forward them to the instance-level _todCollector if one is active.
      this.artnet.on('artTodData', (tod) => {
        if (tod && this._todCollector) this._todCollector(tod)
      })

      this.artnet.on('error', (err) => this.emit('error', err))
    }

    if (startSACN) {
      try {
        await this.sacn.start(bindAddress)

        this.sacn.on('sourceFound', (source) => {
          this.sacnSources.set(source.cid, source)
          this.emit('nodeFound', source)
        })

        this.sacn.on('error', (err) => this.emit('error', err))
      } catch (err) {
        // sACN start failed (e.g. port 5568 in use by Pathscape or another app).
        // This is non-fatal — emit a progress WARNING so it shows up in the scan
        // log, but do NOT emit 'error' (which main.js maps to scan-error and
        // causes the renderer to think the entire scan crashed, re-enabling the
        // Scan button while the Art-Net scan is still running in the background).
        this.emit('progress', {
          message: `⚠ sACN unavailable: port 5568 is already in use (${err.message}). ` +
                   `Continuing with Art-Net only.`
        })
      }
    }
  }

  stop() {
    this.artnet.stop()
    this.sacn.stop()
    this.rdmnet.destroy()
    this.dmxSources.clear()
    this.running = false
    // NOTE: this.broker is intentionally NOT stopped here.  The embedded RDMnet
    // broker must persist between scans so that connected gateways (Pathports)
    // don't lose their TCP connection and have to re-discover/re-connect each scan.
    // Call scanner.destroy() to fully tear down including the broker.
  }

  /**
   * Full teardown — stops the broker in addition to the normal stop().
   * Call this when the app is quitting.
   */
  destroy() {
    this.stop()
    if (this.broker) {
      this.broker.stop()
      // Reset the module-level singleton so that if the Electron process
      // somehow creates a new Scanner after this (edge case), it will
      // attempt a fresh broker.start() rather than reusing a stopped instance.
      _sharedBroker = new RDMnetBroker()
    }
  }

  // ─── Manual Nodes ────────────────────────────────────────────────────────────

  /**
   * Replace the manual node list before a scan starts.
   * Each entry: { ip, name, universes }
   */
  setManualNodes(nodes = []) {
    this.manualNodes.clear()
    for (const n of nodes) {
      this.manualNodes.set(n.ip, {
        ip:          n.ip,
        shortName:   n.name || `Manual Node @ ${n.ip}`,
        longName:    n.name || `Manually added node at ${n.ip}`,
        universes:   n.universes || [{ net: 0, sub: 0, uni: 0 }],
        // Both supportsRDM and protocol are unknown until confirmed by the scan.
        // null = "don't know yet".  The scanner attempts RDM discovery regardless
        // (see the supportsRDM === false guard below), and the protocol label is
        // filled in once an ArtPollReply or equivalent is received.
        supportsRDM: null,
        protocol:    null,
        manual:      true,
      })
    }
  }

  // ─── Art-Net Node Discovery ─────────────────────────────────────────────────

  async discoverNodes() {
    this.nodes.clear()

    // Standard broadcast ArtPoll on all known subnets.
    // Space them 30ms apart — a node on 192.168.1.x can match multiple
    // broadcast addresses (subnet, wider-subnet, global) and would otherwise
    // receive several ArtPolls within microseconds, overwhelming its reply queue.
    for (const bc of this.broadcasts) {
      this.artnet.sendArtPoll(bc)
      await this._delay(30)
    }

    // If a subnet override is set (e.g. "10.30.142"), unicast ArtPoll to every
    // host in that /24. This reaches nodes on remote subnets that don't receive
    // our broadcast (e.g. Pathport nodes on a dedicated lighting network).
    if (this.subnetOverride) {
      const parts = this.subnetOverride.split('.')
      if (parts.length === 3) {
        for (let h = 1; h <= 254; h++) {
          if (!this.running) break  // abort if scanner was stopped
          this.artnet.sendArtPoll(`${this.subnetOverride}.${h}`)
          if (h % 50 === 0) await this._delay(10)
        }
      }
    }

    await this._delay(800)
    // Second-pass broadcasts — same 30ms spacing
    for (const bc of this.broadcasts) {
      this.artnet.sendArtPoll(bc)
      await this._delay(30)
    }
    await this._delay(POLL_WAIT_MS - 800)

    // Follow-up: unicast ArtPoll to any passively-detected ArtDmx sources
    // that haven't yet replied to a broadcast poll. This catches consoles
    // (e.g. GrandMA2) that only respond to direct unicast.
    const unresolved = Array.from(this.dmxSources.keys()).filter(ip => !this.nodes.has(ip))
    if (unresolved.length > 0) {
      for (const ip of unresolved) this.artnet.sendArtPoll(ip)
      await this._delay(600)
      // One more pass for any that were slow to respond
      for (const ip of unresolved) this.artnet.sendArtPoll(ip)
      await this._delay(600)
    }

    // Unicast ArtPoll directly to each manually-added node that hasn't been
    // seen yet. Some nodes (including Pathports in certain firmware versions)
    // silently ignore broadcast ArtPoll but DO reply to unicast directed at
    // their IP.  Sending to the known unicast address ensures we get an
    // ArtPollReply with the node's actual universe configuration.
    const manualUnseen = Array.from(this.manualNodes.keys()).filter(ip => !this.nodes.has(ip))
    if (manualUnseen.length > 0) {
      for (const ip of manualUnseen) this.artnet.sendArtPoll(ip)
      await this._delay(800)
      // Second pass — give slow nodes extra time
      for (const ip of manualUnseen) this.artnet.sendArtPoll(ip)
      await this._delay(800)
    }

    // Inject manually added nodes — they skip ArtPoll entirely
    for (const [ip, node] of this.manualNodes) {
      if (!this.nodes.has(ip)) {
        this.nodes.set(ip, node)
        this.emit('nodeFound', node)
      }
    }

    return Array.from(this.nodes.values())
  }

  // ─── sACN Source Discovery ────────────────────────────────────────────────────

  /**
   * Wait for sACN sources to appear on the network.
   * sACN is passive — we just listen for multicast packets.
   */
  async discoverSACNSources() {
    // Do NOT clear sacnSources here — sources may have been found passively during
    // the mDNS/LLRP phase before this method is called.  Clearing them would drop
    // those sources from the RDM probing pass later.  New sources found during this
    // window are added by the 'sourceFound' event listener on the sacn emitter.
    await this._delay(SACN_LISTEN_MS)
    return Array.from(this.sacnSources.values())
  }

  // ─── Passive ArtDmx Source Tracking ─────────────────────────────────────────

  _registerDmxSource(dmxInfo) {
    const { ip, net, subNet, universe } = dmxInfo
    const uniKey = `${net}.${subNet}.${universe}`

    if (this.dmxSources.has(ip)) {
      const existing = this.dmxSources.get(ip)
      if (!existing._uniSet.has(uniKey)) {
        existing._uniSet.add(uniKey)
        existing.universes.push({ net, sub: subNet, uni: universe })
      }
      existing.lastSeen = Date.now()
      existing.packetCount++
      return
    }

    const source = {
      ip,
      shortName:   `ArtDmx Source @ ${ip}`,
      longName:    `Passively discovered ArtDmx source at ${ip}`,
      universes:   [{ net, sub: subNet, uni: universe }],
      _uniSet:     new Set([uniKey]),
      supportsRDM: false,
      protocol:    'artnet-passive',
      lastSeen:    Date.now(),
      packetCount: 1,
    }
    this.dmxSources.set(ip, source)
    this.emit('nodeFound', source)
  }

  /**
   * Return all passively discovered ArtDmx sources.
   */
  getDmxSources() {
    return Array.from(this.dmxSources.values()).map(s => {
      const { _uniSet, ...clean } = s
      return clean
    })
  }

  // ─── RDM Send / Receive ─────────────────────────────────────────────────────

  async _sendAndReceive(nodeIP, net, sub, uni, packet, timeout = RDM_TIMEOUT_MS) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this._pendingCallback = null
        resolve(null)
      }, timeout)

      // Keep the callback alive until we get a packet from the right IP
      // or the timer fires.  Previous bug: callback was nulled before calling
      // it, then re-assigned only once — losing it after 2 wrong-source packets.
      this._pendingCallback = (data, rinfo) => {
        if (rinfo.address === nodeIP) {
          clearTimeout(timer)
          this._pendingCallback = null
          resolve(data)
        }
        // Wrong source address — leave _pendingCallback intact so we keep
        // waiting.  The timer will clean it up if nothing useful arrives.
      }

      this.artnet.sendArtRdm(nodeIP, net, sub, uni, packet)
    })
  }

  // ─── LLRP RDM Send / Receive ──────────────────────────────────────────────────

  /**
   * Send an RDM command to a device via LLRP (direct UDP, bypasses broker).
   * @param {string} nodeIP    - Device IP
   * @param {Buffer} nodeCID   - Device CID (16 bytes, from LLRP probe reply)
   * @param {Buffer} packet    - RDM packet
   * @param {number} timeout
   */
  async _sendAndReceiveLLRP(nodeIP, nodeCID, packet, timeout = RDM_TIMEOUT_MS) {
    return this.rdmnet.sendLLRPRdm(nodeIP, nodeCID, packet, timeout)
  }

  // ─── RPT RDM Send / Receive ─────────────────────────────────────────────────

  /**
   * Send an RDM command through an RDMnet broker via RPT.
   * @param {Buffer} destUID       - Target device UID (6 bytes)
   * @param {number} destEndpoint  - Target endpoint
   * @param {Buffer} packet        - RDM packet
   * @param {number} timeout
   */
  async _sendAndReceiveRPT(destUID, destEndpoint, packet, timeout = RDM_TIMEOUT_MS, gatewayCIDBuf = null) {
    if (!this.broker || !this.broker.running) return null
    // If a specific gateway CID is provided, use it.  Otherwise fall back to the
    // first connected gateway (for legacy "Try 3" RPT paths).
    let cidBuf = gatewayCIDBuf
    if (!cidBuf) {
      const gateways = this.broker.getConnectedGateways()
      if (gateways.length === 0) return null
      cidBuf = gateways[0].cidBuf
    }
    return this.broker.sendRdm(cidBuf, destUID, destEndpoint, packet, timeout)
  }

  // ─── Multi-Transport RDM Send ───────────────────────────────────────────────

  /**
   * Send an RDM command using the best available transport.
   * @param {string} transport  - 'artnet', 'llrp', or 'rpt'
   * @param {object} ctx        - Transport context (nodeIP, net, sub, uni, nodeCID, destUID, endpoint)
   * @param {Buffer} packet     - RDM packet
   * @param {number} timeout
   */
  async _sendRDM(transport, ctx, packet, timeout = RDM_TIMEOUT_MS) {
    switch (transport) {
      case 'artnet':
        return this._sendAndReceive(ctx.nodeIP, ctx.net, ctx.sub, ctx.uni, packet, timeout)
      case 'llrp':
        return this._sendAndReceiveLLRP(ctx.nodeIP, ctx.nodeCID, packet, timeout)
      case 'rpt':
        return this._sendAndReceiveRPT(ctx.destUID, ctx.endpoint, packet, timeout, ctx.gatewayCIDBuf || null)
      default:
        return null
    }
  }

  // ─── RDM Discovery (Binary Tree) ──────────────────────────────────────────────

  async discoverRDMDevices(nodeIP, net, sub, uni) {
    const found = new Map()

    const unMuteAll = RDM.buildDiscUnMuteAll()
    await this._sendAndReceive(nodeIP, net, sub, uni, unMuteAll, 200)
    await this._delay(80)

    const lower = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    const upper = Buffer.from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

    await this._discoveryBranch(nodeIP, net, sub, uni, lower, upper, found, 0)
    return Array.from(found.entries()).map(([uidStr, uidBuf]) => ({ uidStr, uidBuf }))
  }

  async _discoveryBranch(nodeIP, net, sub, uni, lower, upper, found, depth) {
    if (depth > 50) return

    const dub      = RDM.buildDiscUniqueBranch(lower, upper)
    const response = await this._sendAndReceive(nodeIP, net, sub, uni, dub, RDM_TIMEOUT_MS)

    if (!response) return

    const uid = RDM.parseDiscoveryResponse(response)

    if (uid) {
      const uidStr = RDM.uidToString(uid)
      if (!found.has(uidStr)) {
        const mute = RDM.buildDiscMute(uid)
        await this._sendAndReceive(nodeIP, net, sub, uni, mute, 300)
        found.set(uidStr, uid)
        this.emit('uidFound', { uidStr, nodeIP })
      }
      await this._discoveryBranch(nodeIP, net, sub, uni, lower, upper, found, depth + 1)
    } else {
      const mid = this._midUID(lower, upper)
      if (!mid) return

      await this._discoveryBranch(nodeIP, net, sub, uni, lower, mid, found, depth + 1)

      const midPlus = this._incrementUID(mid)
      if (midPlus) {
        await this._discoveryBranch(nodeIP, net, sub, uni, midPlus, upper, found, depth + 1)
      }
    }
  }

  // ─── ArtTodRequest Discovery ─────────────────────────────────────────────────

  /**
   * Send ArtTodRequest to a node and collect all ArtTodData replies.
   *
   * Returns a Map of `"net.sub.uni"` → `Set<uid_hex_string>`.
   *
   * Unlike binary-tree RDM discovery, ArtTodRequest asks the proxy node for
   * its own cached TOD — it just returns UIDs it already knows about.
   * This works even when the node doesn't proxy individual RDM packets.
   *
   * @param {string} nodeIP    - Unicast IP of the node
   * @param {number} net       - Net switch (0-127), usually 0
   * @param {number} timeoutMs - How long to wait for TOD replies
   */
  /**
   * Request the RDM Table of Devices (TOD) from a proxy node.
   *
   * @param {string}   nodeIP      - Unicast IP of the node
   * @param {number}   net         - Art-Net Net switch (0-127)
   * @param {number}   timeoutMs   - Total wait time for TOD replies
   * @param {number[]|null} subUnis - Specific SubUni values to request (computed
   *   from the node's advertised universes).  Pass null to sweep all 256 — only
   *   needed for nodes with non-standard universe assignments or unknown config.
   *   Sweeping all 256 sends 9 UDP packets in a burst which can overwhelm
   *   embedded hardware (e.g. Pathports); targeted mode sends 1-2 packets total.
   */
  async requestTOD(nodeIP, net = 0, timeoutMs = 2000, subUnis = null) {
    const todMap = new Map()  // `${net}.${sub}.${uni}` → Set<uidHex>

    this._todCollector = (tod) => {
      if (tod.ip !== nodeIP) return
      const key = `${tod.net}.${tod.sub}.${tod.uni}`
      if (!todMap.has(key)) todMap.set(key, new Set())
      for (const uid of tod.uids) todMap.get(key).add(uid.toString('hex'))
    }

    // First: send with AddCount = 0 ("all output universes") per Art-Net 4 spec.
    // Modern firmware (Pathport 6.1+, etc.) will reply to this immediately.
    this.artnet.sendArtTodRequest(nodeIP, net, [])
    await this._delay(400)

    // Fallback sweep for older firmware that ignores AddCount = 0.
    // If the caller supplied specific sub-uni values (computed from the node's
    // advertised universes), only request those — this avoids a 9-packet burst
    // on hardware with limited UDP receive buffers.
    // If subUnis is null, fall back to a full sweep of all 256 (legacy path).
    const sweepList = subUnis !== null ? subUnis : Array.from({ length: 256 }, (_, i) => i)

    if (sweepList.length > 0) {
      const chunkSize = 32
      for (let i = 0; i < sweepList.length; i += chunkSize) {
        this.artnet.sendArtTodRequest(nodeIP, net, sweepList.slice(i, i + chunkSize))
        await this._delay(150)   // 150ms between chunks (was 40ms) — safer for embedded devices
      }
    }

    // Wait the remainder of the timeout for any slow TOD packets to arrive
    const sweepTime = 400 + Math.ceil(sweepList.length / 32) * 150
    const remaining = timeoutMs - sweepTime
    if (remaining > 0) await this._delay(remaining)

    this._todCollector = null
    return todMap
  }

  // ─── Transport-Aware RDM Discovery ──────────────────────────────────────────

  /**
   * Discover RDM devices using a specific transport.
   * @param {string} transport - 'llrp' or 'rpt'
   * @param {object} ctx       - Transport context
   * @returns {Promise<Array<{ uidStr, uidBuf }>>}
   */
  async discoverRDMDevicesVia(transport, ctx) {
    const found = new Map()

    const unMuteAll = RDM.buildDiscUnMuteAll()
    await this._sendRDM(transport, ctx, unMuteAll, 200)
    await this._delay(80)

    const lower = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    const upper = Buffer.from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

    await this._discoveryBranchVia(transport, ctx, lower, upper, found, 0)
    return Array.from(found.entries()).map(([uidStr, uidBuf]) => ({ uidStr, uidBuf }))
  }

  async _discoveryBranchVia(transport, ctx, lower, upper, found, depth) {
    if (depth > 50) return

    const dub      = RDM.buildDiscUniqueBranch(lower, upper)
    const response = await this._sendRDM(transport, ctx, dub, RDM_TIMEOUT_MS)

    if (!response) return

    const uid = RDM.parseDiscoveryResponse(response)

    if (uid) {
      const uidStr = RDM.uidToString(uid)
      if (!found.has(uidStr)) {
        const mute = RDM.buildDiscMute(uid)
        await this._sendRDM(transport, ctx, mute, 300)
        found.set(uidStr, uid)
        this.emit('uidFound', { uidStr, nodeIP: ctx.nodeIP || 'rpt' })
      }
      await this._discoveryBranchVia(transport, ctx, lower, upper, found, depth + 1)
    } else {
      const mid = this._midUID(lower, upper)
      if (!mid) return
      await this._discoveryBranchVia(transport, ctx, lower, mid, found, depth + 1)
      const midPlus = this._incrementUID(mid)
      if (midPlus) {
        await this._discoveryBranchVia(transport, ctx, midPlus, upper, found, depth + 1)
      }
    }
  }

  /**
   * Get device info using a specific transport.
   * Same as getDeviceInfo but transport-agnostic.
   */
  async getDeviceInfoVia(transport, ctx, uidStr, uidBuf) {
    const info = { uid: uidStr, nodeIP: ctx.nodeIP || 'rpt', net: ctx.net || 0, sub: ctx.sub || 0, uni: ctx.uni || 0 }

    const _get = async (pid, pd) => {
      const request = RDM.buildGetRequest(uidBuf, pid, pd)
      const raw = await this._sendRDM(transport, ctx, request, RDM_TIMEOUT_MS)
      if (!raw) return null
      return RDM.parsePacket(raw)
    }

    const diResp = await _get(RDM.PID.DEVICE_INFO)
    if (diResp && diResp.pd) Object.assign(info, RDM.parseDeviceInfo(diResp.pd))

    const mfgResp = await _get(RDM.PID.MANUFACTURER_LABEL)
    if (mfgResp?.pd) info.manufacturerLabel = _parseStr(mfgResp.pd)

    const modelResp = await _get(RDM.PID.DEVICE_MODEL_DESCRIPTION)
    if (modelResp?.pd) info.deviceModelDescription = _parseStr(modelResp.pd)

    const labelResp = await _get(RDM.PID.DEVICE_LABEL)
    if (labelResp?.pd) info.deviceLabel = _parseStr(labelResp.pd)

    const swResp = await _get(RDM.PID.SOFTWARE_VERSION_LABEL)
    if (swResp?.pd) info.softwareVersionLabel = _parseStr(swResp.pd)

    if (info.currentPersonality > 0) {
      const pPD = Buffer.alloc(1)
      pPD[0] = info.currentPersonality
      const persResp = await _get(RDM.PID.DMX_PERSONALITY_DESCRIPTION, pPD)
      if (persResp?.pd && persResp.pd.length >= 3) {
        info.personalityName      = _parseStr(persResp.pd.slice(2))
        info.personalityFootprint = persResp.pd.readUInt16BE(0)
      }
    }

    return info
  }

  // ─── RDM GET / SET ────────────────────────────────────────────────────────────

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

  // ─── Full Device Info ──────────────────────────────────────────────────────────

  async getDeviceInfo(nodeIP, net, sub, uni, uidStr, uidBuf) {
    const info = { uid: uidStr, nodeIP, net, sub, uni }

    const diResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.DEVICE_INFO)
    if (diResp && diResp.pd) Object.assign(info, RDM.parseDeviceInfo(diResp.pd))

    const mfgResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.MANUFACTURER_LABEL)
    if (mfgResp?.pd) info.manufacturerLabel = _parseStr(mfgResp.pd)

    const modelResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.DEVICE_MODEL_DESCRIPTION)
    if (modelResp?.pd) info.deviceModelDescription = _parseStr(modelResp.pd)

    const labelResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.DEVICE_LABEL)
    if (labelResp?.pd) info.deviceLabel = _parseStr(labelResp.pd)

    const swResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.SOFTWARE_VERSION_LABEL)
    if (swResp?.pd) info.softwareVersionLabel = _parseStr(swResp.pd)

    if (info.currentPersonality > 0) {
      const pPD = Buffer.alloc(1)
      pPD[0] = info.currentPersonality
      const persResp = await this.getRDMParam(nodeIP, net, sub, uni, uidBuf, RDM.PID.DMX_PERSONALITY_DESCRIPTION, pPD)
      if (persResp?.pd && persResp.pd.length >= 3) {
        info.personalityName      = _parseStr(persResp.pd.slice(2))
        info.personalityFootprint = persResp.pd.readUInt16BE(0)
      }
    }

    return info
  }

  // ─── Convenience Actions ──────────────────────────────────────────────────────

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

  // ─── Full Scan Workflow ───────────────────────────────────────────────────────

  /**
   * @param {string} bindAddress
   * @param {Function|null} onProgress
   * @param {string} protocol - 'artnet', 'sacn', or 'both'
   */
  async fullScan(bindAddress, onProgress, protocol = 'both') {
    this.running = true
    const scanArtNet = protocol === 'artnet' || protocol === 'both'
    const scanSACN   = protocol === 'sacn'   || protocol === 'both'

    // Convenience: check whether this scanner was stopped mid-scan.
    // If stop() was called (e.g. because a new scan started), bail out
    // early rather than continuing to burn CPU/network on stale work.
    const alive = () => this.running

    const report = (msg, extra = {}) => {
      this.emit('progress', { message: msg, ...extra })
      if (onProgress) onProgress({ message: msg, ...extra })
    }

    try {
      const allDevices = []

      // Emit a timestamped scan header so each scan is clearly delimited in the log
      const iface = bindAddress === '0.0.0.0' ? 'all interfaces' : bindAddress
      const protoLabel = scanArtNet && scanSACN ? 'Art-Net + sACN' : scanArtNet ? 'Art-Net' : 'sACN'
      report(`──────────────────────────────────────────────────────`)
      report(`Scan started: ${new Date().toLocaleString()}`)
      report(`Interface: ${iface}  ·  Protocol: ${protoLabel}`)
      if (this.subnetOverride) report(`Subnet override: ${this.subnetOverride}.0/24`)
      report(`──────────────────────────────────────────────────────`)

      // ── mDNS RDMnet pre-scan (once, before per-node work) ─────────────────
      // Run this early so results are ready to display per-node without
      // re-querying the network 4 times.
      let mdnsRDMnetServices = []
      if (scanArtNet && alive()) {
        report('Pre-scanning for _rdmnet._tcp.local services via mDNS…')
        try {
          mdnsRDMnetServices = await Promise.race([
            this.rdmnet.discoverMDNS(2000),
            new Promise(r => setTimeout(() => r([]), 3500)),
          ])
          if (mdnsRDMnetServices.length > 0) {
            report(`mDNS found ${mdnsRDMnetServices.length} RDMnet broker(s) on the network:`)
            for (const svc of mdnsRDMnetServices) {
              report(`  ${svc.name}  →  ${svc.ip}:${svc.port}`)
            }
          } else {
            report('No _rdmnet._tcp.local brokers found via mDNS.')
          }
        } catch (e) {
          report(`mDNS pre-scan error: ${e.message}`)
        }
      }

      if (!alive()) return allDevices  // scanner was stopped during mDNS

      // ── LLRP Discovery (BEFORE per-node scan to populate device cache) ──
      // E1.33 LLRP probes go to multicast 239.255.250.133:5569 plus unicast
      // to each known manual node IP.  Replies populate rdmnet._llrpDevices
      // so the per-node LLRP fallback has cached CIDs to work with.
      let llrpResults = []
      if (scanArtNet && alive()) {
        const manualIPs = Array.from(this.manualNodes.keys())
        report('Sending E1.33 LLRP probes (multicast 239.255.250.133 + unicast to known nodes)…')
        // Watch the first manual node IP for diagnostic raw-packet counts.
        // This tells us whether the Pathport is responding at all, even if
        // the reply doesn't parse as a valid LLRP probe reply.
        const watchedIP = manualIPs.length > 0 ? manualIPs[0] : null
        if (watchedIP) this.rdmnet.watchIP(watchedIP)
        try {
          llrpResults = await this.rdmnet.broadcastProbe(2500, manualIPs, bindAddress)
          if (llrpResults.length > 0) {
            report(`LLRP: Found ${llrpResults.length} RDMnet device(s):`)
            for (const r of llrpResults) {
              report(`  ${r.ip}  UID: ${r.uidStr || 'n/a'}  CID: ${(r.cid || '').slice(0,16)}…`)
            }
          } else {
            report('LLRP: No RDMnet devices responded to probe.')
          }
        } catch (e) {
          report(`LLRP probe error: ${e.message}`)
        }
        // Report raw-packet diagnostic results for the watched node
        if (watchedIP) {
          const diag = this.rdmnet.stopWatchIP()
          if (diag.count === 0) {
            report(`  LLRP diag (${watchedIP}): 0 UDP packets received on port 5569 — node may not support LLRP, or firewall is blocking replies.`)
          } else {
            report(`  LLRP diag (${watchedIP}): ${diag.count} raw UDP packet(s) received on port 5569:`)
            for (const s of diag.samples) {
              report(`    ${s.len}B from port ${s.port}  ACN=${s.isACN}  hex: ${s.hex}`)
            }
          }
        }
      }

      if (!alive()) return allDevices

      // ── Broker connection ────────────────────────────────────────────────
      // Strategy:
      //   1. If mDNS found brokers, connect to the first one.
      //   2. If mDNS found nothing, try TCP probe to:
      //      a) Each manual node IP (Pathport nodes might expose a broker)
      //      b) Local IPs on the same first-octet subnet (Pathscape on local machine)
      //      c) 127.0.0.1 (Pathscape on this machine)
      let brokerIP = null

      // 1. mDNS-discovered brokers
      if (scanArtNet && mdnsRDMnetServices.length > 0 && alive()) {
        for (const svc of mdnsRDMnetServices) {
          if (!alive()) break
          report(`[RDMnet] Connecting to broker at ${svc.ip}:${svc.port}…`)
          try {
            const conn = await this.rdmnet.connectBroker(svc.ip, svc.port, 5000)
            if (conn.connected) {
              brokerIP = svc.ip
              report(`[RDMnet] ✓ Connected to broker at ${svc.ip} as RPT Controller`)
              if (conn.clients.length > 0) {
                const devices = conn.clients.filter(c => c.clientType === 2)
                report(`[RDMnet]   Broker reports ${devices.length} RPT Device(s):`)
                for (const c of devices) {
                  report(`[RDMnet]     ${c.uidStr} (CID: ${c.cid.slice(0,8)}…)`)
                }
              }
              break  // use first successful broker
            } else {
              report(`[RDMnet] Broker at ${svc.ip} rejected connection: ${conn.error}`)
            }
          } catch (e) {
            report(`[RDMnet] Failed to connect to broker at ${svc.ip}: ${e.message}`)
          }
        }
      }

      // 2. Fallback: if mDNS found no brokers, try TCP to potential broker IPs.
      //    IMPORTANT: Do NOT TCP probe manual node IPs (Pathport endpoints).
      //    Connecting TCP to an RDMnet endpoint that isn't a broker can disrupt
      //    its existing broker connection and knock it offline.
      if (!brokerIP && scanArtNet && alive()) {
        // Collect ALL local IPs (Pathscape might be on any interface)
        const allLocalIPs = _getAllLocalIPs()
        // Collect passively detected ArtDmx source IPs (e.g. Pathscape sending DMX)
        const dmxSourceIPs = Array.from(this.dmxSources.keys())
        // Deduplicate: ArtDmx sources + all local IPs + localhost (NOT manual node IPs)
        const candidateIPs = [...new Set([...dmxSourceIPs, ...allLocalIPs, '127.0.0.1'])]

        report(`[RDMnet] mDNS found no brokers — probing ${candidateIPs.length} candidate IP(s) on TCP port 5569…`)

        for (const ip of candidateIPs) {
          if (!alive() || brokerIP) break
          try {
            const conn = await this.rdmnet.connectBroker(ip, RDMNET_PORT, 2000)
            if (conn.connected) {
              brokerIP = ip
              report(`[RDMnet] ✓ Found broker at ${ip}:${RDMNET_PORT} via TCP probe`)
              if (conn.clients.length > 0) {
                const devices = conn.clients.filter(c => c.clientType === 2)
                report(`[RDMnet]   Broker reports ${devices.length} RPT Device(s):`)
                for (const c of devices) {
                  report(`[RDMnet]     ${c.uidStr} (CID: ${c.cid.slice(0,8)}…)`)
                }
              }
            }
          } catch (_) {}
        }
        if (!brokerIP) {
          report(`[RDMnet] No brokers found via TCP probe.`)
        }
      }

      if (!alive()) return allDevices

      // ── Embedded RDMnet Broker — Gateway Discovery ────────────────────────
      // Check for gateways (Pathports, etc.) that have connected to this app's
      // own built-in RDMnet broker on TCP port 5569.  These devices are
      // configured with "RDM Transport: E1.33 RDMnet (Unsecured)" in Pathscape
      // and connect automatically when the app is running.
      const embeddedGateways = this.broker ? this.broker.getConnectedGateways() : []
      if (embeddedGateways.length > 0) {
        report(`Embedded RDMnet broker: ${embeddedGateways.length} gateway(s) connected — scanning for RDM devices…`)

        for (const gw of embeddedGateways) {
          if (!alive()) break

          report(`Scanning RDMnet gateway: ${gw.ip} (UID: ${gw.uid})`)

          // Emit gateway as a node so it appears in the UI
          const gwNode = {
            ip:          gw.ip,
            shortName:   `RDMnet GW @ ${gw.ip}`,
            longName:    `RDMnet Gateway  UID:${gw.uid}`,
            protocol:    'rdmnet',
            supportsRDM: true,
            cid:         gw.cidHex,
            uid:         gw.uid,
          }
          if (!this.nodes.has(gw.ip)) {
            this.nodes.set(gw.ip, gwNode)
            this.emit('nodeFound', gwNode)
          }

          const broadcastUID   = Buffer.from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
          let   gwFoundDevices = false

          // Pathport 8-port → try endpoints 1–8 (one per physical DMX port)
          for (let ep = 1; ep <= 8; ep++) {
            if (!alive()) break

            const ctx = {
              destUID:       broadcastUID,
              endpoint:      ep,
              gatewayCIDBuf: gw.cidBuf,
              nodeIP:        gw.ip,
            }

            report(`  [RPT] Discovering on endpoint ${ep}…`)
            let uids = []
            try {
              uids = await this.discoverRDMDevicesVia('rpt', ctx)
            } catch (_) { continue }

            if (uids.length === 0) continue

            gwFoundDevices = true
            report(`  ✓ Found ${uids.length} RDM UID(s) on endpoint ${ep}`)

            for (const { uidStr, uidBuf } of uids) {
              if (!alive()) break
              report(`    Reading: ${uidStr}`)
              try {
                const deviceInfo = await this.getDeviceInfoVia('rpt', ctx, uidStr, uidBuf)
                deviceInfo.universe  = `EP${ep}`
                deviceInfo.nodeName  = gwNode.shortName
                deviceInfo.nodeIP    = gw.ip
                deviceInfo.protocol  = 'rdmnet-rpt'
                deviceInfo.transport = 'RDMnet RPT (embedded broker)'
                allDevices.push(deviceInfo)
                this.emit('deviceFound', deviceInfo)
              } catch (e) {
                report(`    Error reading ${uidStr}: ${e.message}`)
              }
            }
          }

          if (!gwFoundDevices) {
            report(`  [RPT] No RDM devices found on gateway ${gw.ip}.`)
            report(`         Verify that RDM fixtures are connected to the Pathport's physical ports`)
            report(`         and that RDM is enabled on those ports in Pathscape.`)
          }
        }
      } else if (this.broker && this.broker.running) {
        const mDNSIPs = this.broker.mDNSIPs || []
        const mDNSErr = this.broker.mDNSError
        if (mDNSErr) {
          report(`Embedded RDMnet broker running (port 5569) — mDNS ERROR: ${mDNSErr}`)
          report(`  Pathports cannot auto-discover the broker. Check for conflicts on port 5353.`)
        } else if (mDNSIPs.length > 0) {
          report(`Embedded RDMnet broker running (port 5569) — no gateways connected.`)
          report(`  mDNS advertising on: ${mDNSIPs.join(', ')}`)
          report(`  If Pathports are configured for E1.33 RDMnet (Unsecured) but still not connecting:`)
          report(`  • macOS firewall may be blocking port 5569 — check System Settings → Privacy &`)
          report(`    Security → Firewall → ensure RDM Explorer (or Electron) is set to Allow`)
          report(`  • Try re-applying Pathport settings: in Pathscape select each Pathport → Send All`)
          report(`    (this re-triggers the Pathport's mDNS broker lookup)`)
        } else {
          report(`Embedded RDMnet broker running (port 5569) — mDNS not yet started, wait and re-scan.`)
        }
      }

      if (!alive()) return allDevices

      // ── Early sACN Discovery ──────────────────────────────────────────────
      // Run sACN discovery BEFORE Art-Net node scanning so that sACN source
      // data is available for diagnostics (e.g. confirming a Pathport is alive
      // even though it doesn't respond to Art-Net).
      if (scanSACN && alive()) {
        report('Listening for sACN sources on the network…')
        const earlySACNSources = await this.discoverSACNSources()

        if (earlySACNSources.length === 0) {
          report('No sACN sources found.')
        } else {
          report(`Found ${earlySACNSources.length} sACN source(s).`, { nodes: earlySACNSources })
          for (const src of earlySACNSources) {
            const uniList = src.universes.map(u => u.universe || u.uni).join(', ')
            report(`  ${src.shortName || src.sourceName || src.ip} (${src.ip}) — universes: ${uniList}`)

            // NOTE: do NOT re-emit 'nodeFound' here.  The sacn.on('sourceFound')
            // listener already emitted it when the source was first discovered.
            // Re-emitting would cause duplicate entries in the renderer and log.

            // Flag if this sACN source matches a manual node IP
            if (this.manualNodes.has(src.ip)) {
              report(`  ↳ Matches manual node ${src.ip} — device is alive on the network (using sACN)`)
            }
          }
        }
      }

      if (!alive()) return allDevices

      // ── Art-Net Discovery ──────────────────────────────────────────────────
      if (scanArtNet) {
        report(`Sending ArtPoll to: ${this.broadcasts.join(', ')}${this.subnetOverride ? ` + unicast sweep of ${this.subnetOverride}.1–254` : ''}`)
        report('Searching for Art-Net nodes on the network…')
        const nodes = await this.discoverNodes()
        if (!alive()) return allDevices  // stopped during ArtPoll wait

        if (nodes.length === 0) {
          report('No Art-Net nodes found.')
        } else {
          report(`Found ${nodes.length} Art-Net node(s). Starting RDM discovery…`, { nodes })

          for (const node of nodes) {
            if (!alive()) break  // scanner stopped — exit node loop immediately

            report(`Scanning node: ${node.shortName} (${node.ip})`)

            // ── Connectivity pre-check for manually added nodes ──────────────
            if (node.manual) {
              report(`  [ping] Checking connectivity to ${node.ip}…`)
              const reachable = await this._pingHost(node.ip)
              if (reachable) {
                report(`  [ping] ${node.ip} is reachable ✓`)
              } else {
                report(`  [ping] WARNING: ${node.ip} did not respond to ping — skipping.`)
                report(`         FIX: Configure a NIC on the same subnet as the node.`)
                continue
              }
            }

            // supportsRDM === false  → confirmed no RDM, skip.
            // supportsRDM === null   → unknown (manual node not yet confirmed via ArtPollReply),
            //                         attempt discovery anyway.
            // supportsRDM === true   → confirmed, proceed.
            if (node.supportsRDM === false) {
              report(`  ${node.shortName} does not support RDM — skipping RDM scan.`)
              continue
            }

            const universesToScan = node.universes.length > 0
              ? node.universes
              : [{ net: 0, sub: 0, uni: 0 }]

            let nodeFoundAnyDevices = false
            let nodeUsedTransport   = null  // track which transport found devices

            // Start watching ALL raw UDP packets from this node (diagnostic)
            if (node.manual) this.artnet.watchIP(node.ip)

            // ── Try 1: Art-Net RDM ──────────────────────────────────────────
            // For manual nodes that never replied to ArtPoll (protocol === null),
            // bail early after 2 consecutive empty universes — if the node isn't
            // sending any Art-Net back, hammering all remaining universes only
            // floods the network and can cause hardware disconnects.
            let consecutiveArtEmpty = 0
            const ART_EMPTY_BAIL = 2

            for (let uniIdx = 0; uniIdx < universesToScan.length; uniIdx++) {
              if (!alive()) break
              const uniInfo  = universesToScan[uniIdx]
              const uniLabel = `${uniInfo.net}.${uniInfo.sub}.${uniInfo.uni}`
              report(`  [Art-Net] Discovering RDM on universe ${uniLabel} → ${node.ip}:6454`)

              let uids = []
              try {
                uids = await this.discoverRDMDevices(node.ip, uniInfo.net, uniInfo.sub, uniInfo.uni)
              } catch (e) {
                report(`  Error on universe ${uniLabel}: ${e.message}`)
                continue
              }

              if (uids.length === 0) {
                report(`  No RDM devices on universe ${uniLabel} via Art-Net.`)
                consecutiveArtEmpty++
                if (node.manual && node.protocol === null && consecutiveArtEmpty >= ART_EMPTY_BAIL) {
                  const remaining = universesToScan.length - uniIdx - 1
                  if (remaining > 0) {
                    report(`  [Art-Net] No Art-Net response from ${node.ip} after ${consecutiveArtEmpty} universe(s) — skipping remaining ${remaining}. Will try TOD/LLRP.`)
                  }
                  break
                }
                continue
              }

              consecutiveArtEmpty = 0
              nodeFoundAnyDevices = true
              nodeUsedTransport   = 'artnet'
              report(`  ✓ Found ${uids.length} RDM UID(s) on universe ${uniLabel} via Art-Net`)

              for (const { uidStr, uidBuf } of uids) {
                report(`    Reading: ${uidStr}`)
                try {
                  const deviceInfo = await this.getDeviceInfo(
                    node.ip, uniInfo.net, uniInfo.sub, uniInfo.uni, uidStr, uidBuf
                  )
                  deviceInfo.universe  = uniLabel
                  deviceInfo.nodeName  = node.shortName
                  deviceInfo.nodeIP    = node.ip
                  deviceInfo.protocol  = 'artnet'
                  deviceInfo.transport = 'Art-Net RDM'
                  allDevices.push(deviceInfo)
                  this.emit('deviceFound', deviceInfo)
                } catch (e) {
                  report(`    Error reading ${uidStr}: ${e.message}`)
                }
              }
            }

            // ── Try 1.5: ArtTodRequest (proxy-mode TOD harvest) ────────────
            // For proxy nodes like the Pathport, the node maintains its own
            // RDM cache.  ArtTodRequest asks "give me your complete list of
            // known RDM UIDs" rather than running binary-tree discovery through
            // the node — this is more reliable when the node doesn't faithfully
            // proxy individual RDM packets.
            if (!nodeFoundAnyDevices && alive()) {
              report(`  [TOD] Trying ArtTodRequest (proxy node RDM harvest) on ${node.ip}…`)
              // Compute the specific SubUni values from the node's advertised universes
              // so we only request those, not all 256 (which can overwhelm embedded devices).
              // SubUni byte = (sub << 4) | uni per Art-Net 4 spec.
              const targetSubUnis = node.universes && node.universes.length > 0
                ? [...new Set(node.universes.map(u => ((u.sub & 0xF) << 4) | (u.uni & 0xF)))]
                : null  // null → full 256 sweep (unknown node)
              const todMap = await this.requestTOD(node.ip, 0, 2500, targetSubUnis)

              if (todMap.size === 0) {
                report(`  [TOD] No ArtTodData reply from ${node.ip} — node may not support ArtTodRequest.`)
              } else {
                report(`  [TOD] ${node.ip} responded with TOD data on ${todMap.size} universe(s):`)
                for (const [uniKey, uidHexSet] of todMap) {
                  if (!alive()) break
                  const [netS, subS, uniS] = uniKey.split('.').map(Number)
                  report(`  [TOD] Universe ${uniKey}: ${uidHexSet.size} UID(s)`)

                  for (const uidHex of uidHexSet) {
                    if (!alive()) break
                    const uidBuf = Buffer.from(uidHex, 'hex')
                    const uidStr = RDM.uidToString(uidBuf)
                    report(`    Reading device info: ${uidStr}`)
                    try {
                      const deviceInfo = await this.getDeviceInfo(
                        node.ip, netS, subS, uniS, uidStr, uidBuf
                      )
                      deviceInfo.universe  = uniKey
                      deviceInfo.nodeName  = node.shortName
                      deviceInfo.nodeIP    = node.ip
                      deviceInfo.protocol  = 'artnet-tod'
                      deviceInfo.transport = 'Art-Net TOD'
                      allDevices.push(deviceInfo)
                      nodeFoundAnyDevices = true
                      nodeUsedTransport   = 'artnet-tod'
                      this.emit('deviceFound', deviceInfo)
                    } catch (e) {
                      report(`    Error reading ${uidStr}: ${e.message}`)
                    }
                  }
                }
                if (!nodeFoundAnyDevices) {
                  report(`  [TOD] TOD data received but no device info could be read.`)
                }
              }
            }

            // ── Stop diagnostic watch ──────────────────────────────────────
            let watchResult = null
            if (node.manual) watchResult = this.artnet.stopWatchIP()

            // ── Try 2: LLRP RDM (if Art-Net found nothing) ─────────────────
            if (!nodeFoundAnyDevices && alive()) {
              let llrpDev = this.rdmnet.getLLRPDevice(node.ip)

              // If the broadcast probe didn't cache this IP, try a direct
              // unicast LLRP probe — the device might only respond to unicast
              // or multicast didn't reach it due to network topology.
              if (!llrpDev) {
                report(`  [LLRP] No cached CID for ${node.ip} — sending direct LLRP probe…`)
                try {
                  const directReply = await this.rdmnet.probeIPDirect(node.ip, 1500)
                  if (directReply) {
                    report(`  [LLRP] ✓ Got LLRP reply from ${node.ip}: UID ${directReply.uidStr || 'n/a'}`)
                    llrpDev = this.rdmnet.getLLRPDevice(node.ip)
                  } else {
                    report(`  [LLRP] No LLRP reply from ${node.ip}.`)
                  }
                } catch (_) {}
              }

              if (llrpDev) {
                report(`  [LLRP] Art-Net RDM yielded nothing — trying LLRP RDM (CID: ${llrpDev.cid.toString('hex').slice(0,8)}…)`)

                for (const uniInfo of universesToScan) {
                  if (!alive()) break
                  const uniLabel = `${uniInfo.net}.${uniInfo.sub}.${uniInfo.uni}`
                  const ctx = { nodeIP: node.ip, nodeCID: llrpDev.cid, net: uniInfo.net, sub: uniInfo.sub, uni: uniInfo.uni }

                  let uids = []
                  try {
                    uids = await this.discoverRDMDevicesVia('llrp', ctx)
                  } catch (e) {
                    report(`  [LLRP] Error on universe ${uniLabel}: ${e.message}`)
                    continue
                  }

                  if (uids.length === 0) continue

                  nodeFoundAnyDevices = true
                  nodeUsedTransport   = 'llrp'
                  report(`  ✓ Found ${uids.length} RDM UID(s) on universe ${uniLabel} via LLRP`)

                  for (const { uidStr, uidBuf } of uids) {
                    report(`    Reading: ${uidStr}`)
                    try {
                      const deviceInfo = await this.getDeviceInfoVia('llrp', ctx, uidStr, uidBuf)
                      deviceInfo.universe  = uniLabel
                      deviceInfo.nodeName  = node.shortName
                      deviceInfo.nodeIP    = node.ip
                      deviceInfo.protocol  = 'rdmnet-llrp'
                      deviceInfo.transport = 'LLRP RDM'
                      allDevices.push(deviceInfo)
                      this.emit('deviceFound', deviceInfo)
                    } catch (e) {
                      report(`    Error reading ${uidStr}: ${e.message}`)
                    }
                  }
                }

                if (!nodeFoundAnyDevices) {
                  report(`  [LLRP] No RDM devices found via LLRP.`)
                }
              }
            }

            // ── Try 3: RPT through broker (if LLRP also found nothing) ──────
            if (!nodeFoundAnyDevices && brokerIP && alive()) {
              report(`  [RPT] Trying RDM discovery through broker at ${brokerIP}…`)

              // Find the RPT Device entry for this node in the broker's client list
              const brokerClients = this.rdmnet.getBrokerClients(brokerIP)
              // Try to match by IP or just try all device clients
              // RPT devices are identified by UID, not IP — try each device's endpoints
              const devicesToTry = brokerClients.length > 0 ? brokerClients : []

              if (devicesToTry.length === 0) {
                // No RPT devices known — try sending RDM to broadcast UID on sequential endpoints
                report(`  [RPT] No RPT Devices reported by broker — trying discovery on endpoints 1-8…`)
                const broadcastUID = Buffer.from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])

                for (let ep = 1; ep <= 8; ep++) {
                  if (!alive()) break
                  const ctx = { destUID: broadcastUID, endpoint: ep, nodeIP: node.ip }
                  let uids = []
                  try {
                    uids = await this.discoverRDMDevicesVia('rpt', ctx)
                  } catch (_) { continue }

                  if (uids.length > 0) {
                    nodeFoundAnyDevices = true
                    nodeUsedTransport   = 'rpt'
                    report(`  ✓ Found ${uids.length} RDM UID(s) on endpoint ${ep} via RPT broker`)

                    for (const { uidStr, uidBuf } of uids) {
                      report(`    Reading: ${uidStr}`)
                      try {
                        const deviceInfo = await this.getDeviceInfoVia('rpt', ctx, uidStr, uidBuf)
                        deviceInfo.universe  = `EP${ep}`
                        deviceInfo.nodeName  = node.shortName
                        deviceInfo.nodeIP    = node.ip
                        deviceInfo.protocol  = 'rdmnet-rpt'
                        deviceInfo.transport = 'RPT (broker)'
                        allDevices.push(deviceInfo)
                        this.emit('deviceFound', deviceInfo)
                      } catch (e) {
                        report(`    Error reading ${uidStr}: ${e.message}`)
                      }
                    }
                  }
                }
              } else {
                // Try each known RPT Device's endpoints
                for (const dev of devicesToTry) {
                  if (!alive()) break
                  const devUID = Buffer.from(dev.uid, 'hex')
                  report(`  [RPT] Trying device ${dev.uidStr} via broker…`)

                  for (let ep = 1; ep <= 8; ep++) {
                    if (!alive()) break
                    const ctx = { destUID: devUID, endpoint: ep, nodeIP: node.ip }

                    let uids = []
                    try {
                      uids = await this.discoverRDMDevicesVia('rpt', ctx)
                    } catch (_) { continue }

                    if (uids.length > 0) {
                      nodeFoundAnyDevices = true
                      nodeUsedTransport   = 'rpt'
                      report(`  ✓ Found ${uids.length} RDM UID(s) on ${dev.uidStr} endpoint ${ep} via RPT`)

                      for (const { uidStr, uidBuf } of uids) {
                        report(`    Reading: ${uidStr}`)
                        try {
                          const deviceInfo = await this.getDeviceInfoVia('rpt', ctx, uidStr, uidBuf)
                          deviceInfo.universe  = `EP${ep}`
                          deviceInfo.nodeName  = node.shortName
                          deviceInfo.nodeIP    = node.ip
                          deviceInfo.protocol  = 'rdmnet-rpt'
                          deviceInfo.transport = 'RPT (broker)'
                          allDevices.push(deviceInfo)
                          this.emit('deviceFound', deviceInfo)
                        } catch (e) {
                          report(`    Error reading ${uidStr}: ${e.message}`)
                        }
                      }
                    }
                  }
                }
              }

              if (!nodeFoundAnyDevices) {
                report(`  [RPT] No RDM devices found via broker.`)
              }
            }

            // ── Diagnostic summary for manual nodes ────────────────────────
            if (node.manual && !nodeFoundAnyDevices) {
              if (watchResult && watchResult.count === 0) {
                report(`  [diag] ${node.ip} sent 0 Art-Net packets back.`)
              }
              if (watchResult && watchResult.count > 0) {
                report(`  [diag] Received ${watchResult.count} packet(s) from ${node.ip}:`)
                for (const s of (watchResult.samples || [])) {
                  const proto = s.isArtNet
                    ? `Art-Net opCode 0x${(s.opCode || 0).toString(16).toUpperCase().padStart(4, '0')}`
                    : `NON-Art-Net`
                  report(`    ${s.len} bytes  ${proto}  header: ${s.header}`)
                }
              }

              // Identify the device via ARP/MAC to give targeted advice
              const macInfo = await this._lookupMAC(node.ip)
              if (macInfo) {
                report(`  [diag] MAC address: ${macInfo.mac}  Vendor: ${macInfo.vendor}`)
              }

              const isPathway = macInfo && macInfo.vendor === 'Pathway'
              const isMAgrandMA = macInfo && (macInfo.vendor === 'MA Lighting' || macInfo.vendor === 'grandMA')

              report(`  NOTE: No RDM devices found on ${node.shortName} via any transport.`)

              if (isPathway) {
                const brokerGateways = this.broker ? this.broker.getConnectedGateways() : []
                const thisGatewayConnected = brokerGateways.some(g => g.ip === node.ip)
                report(`  ╔════════════════════════════════════════════════════════════════╗`)
                report(`  ║  PATHWAY PATHPORT DETECTED                                    ║`)
                report(`  ║                                                                ║`)
                report(`  ║  Pathports use "E1.33 RDMnet (Unsecured)" for RDM access.     ║`)
                report(`  ║  Art-Net RDM is NOT supported by Pathport firmware — only      ║`)
                report(`  ║  Pathway's proprietary RDM or open RDMnet (E1.33) are          ║`)
                report(`  ║  available in Pathscape under Network RDM Protocol.            ║`)
                report(`  ║                                                                ║`)
                report(`  ║  RDM Explorer has a built-in RDMnet broker.                   ║`)
                if (thisGatewayConnected) {
                  report(`  ║  ✓ This Pathport IS connected to the broker — but no RDM     ║`)
                  report(`  ║    devices were found on endpoints 1-8.  Check that RDM      ║`)
                  report(`  ║    fixtures are powered and addressed on this gateway's       ║`)
                  report(`  ║    physical DMX ports.                                        ║`)
                } else {
                  report(`  ║  ✗ This Pathport has NOT connected to the broker yet.        ║`)
                  report(`  ║                                                                ║`)
                  report(`  ║  TO SET UP:                                                   ║`)
                  report(`  ║   1. In Pathscape: Properties → Network RDM Protocol         ║`)
                  report(`  ║      → select "E1.33 RDMnet (Unsecured)"                     ║`)
                  report(`  ║   2. Click "Send All" to apply                                ║`)
                  report(`  ║   3. Leave RDM Explorer running for ~30 s — the Pathport     ║`)
                  report(`  ║      will discover this app via mDNS and connect              ║`)
                  report(`  ║   4. Run a new scan — the Pathport should now appear as       ║`)
                  report(`  ║      a connected gateway with RDM devices found               ║`)
                  report(`  ║                                                                ║`)
                  report(`  ║  NOTE: Pathscape itself has no RDMnet broker — opening it     ║`)
                  report(`  ║  does not help. RDM Explorer IS the broker.                  ║`)
                }
                report(`  ╚════════════════════════════════════════════════════════════════╝`)
              } else if (isMAgrandMA) {
                report(`  ╔════════════════════════════════════════════════════════════════╗`)
                report(`  ║  MA LIGHTING DEVICE DETECTED                                  ║`)
                report(`  ║                                                                ║`)
                report(`  ║  This device did not respond to Art-Net ArtPoll.               ║`)
                report(`  ║  MA devices using only MAnet will not respond to Art-Net.       ║`)
                report(`  ║                                                                ║`)
                report(`  ║  If this is a console or grandMA onPC:                         ║`)
                report(`  ║   • grandMA2: Setup → Network Protocols → Art-Net → Enable     ║`)
                report(`  ║   • grandMA3: Menu → Network → Protocols → Art-Net output      ║`)
                report(`  ║                                                                ║`)
                report(`  ║  If this is a media server using MAnet only:                    ║`)
                report(`  ║   • MAnet is a proprietary protocol — not discoverable here     ║`)
                report(`  ║   • The server needs Art-Net output enabled to be discovered    ║`)
                report(`  ╚════════════════════════════════════════════════════════════════╝`)
              } else if (!brokerIP && mdnsRDMnetServices.length === 0) {
                report(`  [diag] No RDMnet broker found on the network.`)
                report(`         If this device supports E1.33 RDMnet, open its RDMnet broker`)
                report(`         application (e.g. Pathscape for Pathway nodes) and re-scan.`)
              }

              // Check if this IP was seen as an sACN source — confirms it's alive
              const sacnMatch = Array.from(this.sacnSources.values()).find(s => s.ip === node.ip)
              if (sacnMatch) {
                const uniList = sacnMatch.universes
                  ? sacnMatch.universes.map(u => u.universe || u.uni).join(', ')
                  : '?'
                report(`  [diag] NOTE: ${node.ip} IS actively transmitting sACN (universes: ${uniList})`)
                report(`         The node is alive on the network but not responding to Art-Net.`)
                if (isPathway) {
                  report(`         Art-Net RX is likely disabled on this Pathport — see above.`)
                } else if (isMAgrandMA) {
                  report(`         This MA device is sending sACN but not Art-Net.`)
                  report(`         Check that Art-Net output is also enabled in the console/onPC settings.`)
                } else {
                  report(`         This device uses sACN but may not have Art-Net enabled.`)
                }
              }
            }

            if (nodeUsedTransport) {
              report(`  Transport used: ${nodeUsedTransport}`)
            }
          }
        }
      }

      // ── sACN-only Node RDM Discovery ─────────────────────────────────────
      // sACN sources that were NOT already found via Art-Net ArtPollReply
      // need separate RDM probing.  Art-Net RDM won't work (they don't speak
      // Art-Net), but LLRP and RDMnet broker (RPT) are transport-agnostic.
      if (scanSACN && this.sacnSources.size > 0 && alive()) {
        // Collect sACN-only IPs (skip those already covered by Art-Net scan)
        const artnetIPs = scanArtNet ? new Set(Array.from(this.nodes.values()).map(n => n.ip)) : new Set()
        const sacnOnly = Array.from(this.sacnSources.values())
          .filter(s => !artnetIPs.has(s.ip))

        if (sacnOnly.length > 0) {
          report(`\n── sACN-only Node RDM Discovery ──────────────────────────────`)
          report(`${sacnOnly.length} sACN source(s) not found via Art-Net — probing via LLRP/RDMnet…`)

          for (const src of sacnOnly) {
            if (!alive()) break
            const srcName = src.shortName || src.sourceName || src.ip
            report(`Scanning sACN node: ${srcName} (${src.ip})`)

            let nodeFoundAnyDevices = false
            let nodeUsedTransport   = null
            const universesToScan   = (src.universes && src.universes.length > 0)
              ? src.universes
              : [{ net: 0, sub: 0, uni: 0, universe: 1 }]

            // Identify via MAC for diagnostics
            const macInfo = await this._lookupMAC(src.ip)
            if (macInfo) {
              report(`  [diag] MAC address: ${macInfo.mac}  Vendor: ${macInfo.vendor}`)
            }

            // ── LLRP RDM ──────────────────────────────────────────────────
            if (!nodeFoundAnyDevices && alive()) {
              let llrpDev = this.rdmnet.getLLRPDevice(src.ip)

              if (!llrpDev) {
                report(`  [LLRP] No cached CID for ${src.ip} — sending direct LLRP probe…`)
                try {
                  const directReply = await this.rdmnet.probeIPDirect(src.ip, 1500)
                  if (directReply) {
                    report(`  [LLRP] ✓ Got LLRP reply from ${src.ip}: UID ${directReply.uidStr || 'n/a'}`)
                    llrpDev = this.rdmnet.getLLRPDevice(src.ip)
                  } else {
                    report(`  [LLRP] No LLRP reply from ${src.ip}.`)
                  }
                } catch (_) {}
              }

              if (llrpDev) {
                report(`  [LLRP] Trying LLRP RDM on ${src.ip} (CID: ${llrpDev.cid.toString('hex').slice(0,8)}…)`)

                for (const uniInfo of universesToScan) {
                  if (!alive()) break
                  const uni = uniInfo.universe || uniInfo.uni || 0
                  const net = uniInfo.net || 0
                  const sub = uniInfo.sub || 0
                  const uniLabel = `${net}.${sub}.${uni}`
                  const ctx = { nodeIP: src.ip, nodeCID: llrpDev.cid, net, sub, uni }

                  let uids = []
                  try {
                    uids = await this.discoverRDMDevicesVia('llrp', ctx)
                  } catch (e) {
                    report(`  [LLRP] Error on universe ${uniLabel}: ${e.message}`)
                    continue
                  }

                  if (uids.length === 0) continue

                  nodeFoundAnyDevices = true
                  nodeUsedTransport   = 'llrp'
                  report(`  ✓ Found ${uids.length} RDM UID(s) on universe ${uniLabel} via LLRP`)

                  for (const { uidStr, uidBuf } of uids) {
                    report(`    Reading: ${uidStr}`)
                    try {
                      const deviceInfo = await this.getDeviceInfoVia('llrp', ctx, uidStr, uidBuf)
                      deviceInfo.universe  = uniLabel
                      deviceInfo.nodeName  = srcName
                      deviceInfo.nodeIP    = src.ip
                      deviceInfo.protocol  = 'rdmnet-llrp'
                      deviceInfo.transport = 'LLRP RDM (sACN node)'
                      allDevices.push(deviceInfo)
                      this.emit('deviceFound', deviceInfo)
                    } catch (e) {
                      report(`    Error reading ${uidStr}: ${e.message}`)
                    }
                  }
                }

                if (!nodeFoundAnyDevices) {
                  report(`  [LLRP] No RDM devices found via LLRP.`)
                }
              }
            }

            // ── RPT through broker ────────────────────────────────────────
            if (!nodeFoundAnyDevices && brokerIP && alive()) {
              report(`  [RPT] Trying RDM discovery through broker at ${brokerIP}…`)
              const brokerClients = this.rdmnet.getBrokerClients(brokerIP)
              const devicesToTry = brokerClients.length > 0 ? brokerClients : []

              for (const client of devicesToTry) {
                if (!alive()) break
                if (client.ip && client.ip !== src.ip) continue

                report(`  [RPT] Probing broker client UID ${client.uidStr || '?'}`)
                for (const uniInfo of universesToScan) {
                  if (!alive()) break
                  const uni = uniInfo.universe || uniInfo.uni || 0
                  const net = uniInfo.net || 0
                  const sub = uniInfo.sub || 0
                  const uniLabel = `${net}.${sub}.${uni}`
                  const ctx = {
                    brokerIP, nodeIP: src.ip,
                    nodeUID: client.uid, nodeCID: client.cid,
                    net, sub, uni,
                  }

                  let uids = []
                  try {
                    uids = await this.discoverRDMDevicesVia('rpt', ctx)
                  } catch (e) {
                    report(`  [RPT] Error on universe ${uniLabel}: ${e.message}`)
                    continue
                  }

                  if (uids.length === 0) continue

                  nodeFoundAnyDevices = true
                  nodeUsedTransport   = 'rpt'
                  report(`  ✓ Found ${uids.length} RDM UID(s) on universe ${uniLabel} via RPT broker`)

                  for (const { uidStr, uidBuf } of uids) {
                    report(`    Reading: ${uidStr}`)
                    try {
                      const deviceInfo = await this.getDeviceInfoVia('rpt', ctx, uidStr, uidBuf)
                      deviceInfo.universe  = uniLabel
                      deviceInfo.nodeName  = srcName
                      deviceInfo.nodeIP    = src.ip
                      deviceInfo.protocol  = 'rdmnet-rpt'
                      deviceInfo.transport = 'RPT Broker (sACN node)'
                      allDevices.push(deviceInfo)
                      this.emit('deviceFound', deviceInfo)
                    } catch (e) {
                      report(`    Error reading ${uidStr}: ${e.message}`)
                    }
                  }
                }
              }

              if (!nodeFoundAnyDevices) {
                report(`  [RPT] No RDM devices found via broker.`)
              }
            }

            // ── sACN Node Diagnostic Summary ────────────────────────────────
            if (!nodeFoundAnyDevices) {
              const isPathway = macInfo && macInfo.vendor === 'Pathway'
              const isMA      = macInfo && macInfo.vendor === 'MA Lighting'

              report(`  NOTE: No RDM devices found on ${srcName} via any transport.`)

              if (isPathway) {
                report(`  ╔════════════════════════════════════════════════════════════════╗`)
                report(`  ║  PATHWAY PATHPORT — sACN ACTIVE, RDM NOT AVAILABLE            ║`)
                report(`  ║                                                                ║`)
                report(`  ║  This Pathport is transmitting sACN but did not respond to      ║`)
                report(`  ║  LLRP or RDMnet probes.                                        ║`)
                report(`  ║                                                                ║`)
                report(`  ║  For RDM access, configure in Pathscape:                        ║`)
                report(`  ║   1. Network RDM Protocol → "E1.33 RDMnet (Unsecured)"         ║`)
                report(`  ║      (default "Pathway RDM" is proprietary — won't work here)  ║`)
                report(`  ║   2. OR: Open Pathscape with its RDMnet broker enabled          ║`)
                report(`  ║      so this app can discover via broker connection              ║`)
                report(`  ║                                                                ║`)
                report(`  ║  Art-Net RX can also be enabled separately for Art-Net RDM.     ║`)
                report(`  ╚════════════════════════════════════════════════════════════════╝`)
              } else if (isMA) {
                report(`  This MA Lighting device is sending sACN but has no RDMnet/LLRP support.`)
                report(`  MA consoles/onPC do not support E1.33 RDMnet.`)
                report(`  RDM requires Art-Net output to be enabled on this device.`)
              } else {
                report(`  This sACN source does not support LLRP or RDMnet for RDM access.`)
                report(`  Some devices only support RDM via Art-Net — enable Art-Net output on the device.`)
              }
            }

            if (nodeUsedTransport) {
              report(`  Transport used: ${nodeUsedTransport}`)
            }
          }
        } else {
          report(`sACN: ${this.sacnSources.size} source(s) detected — all already covered by Art-Net scan.`)
        }
      } else if (scanSACN && this.sacnSources.size > 0) {
        report(`sACN: ${this.sacnSources.size} source(s) total detected during scan.`)
      }

      // Report passive ArtDmx sources that weren't found via ArtPollReply
      if (scanArtNet && this.dmxSources.size > 0) {
        const passiveOnly = Array.from(this.dmxSources.values())
          .filter(s => !this.nodes.has(s.ip))
        if (passiveOnly.length > 0) {
          report(`Detected ${passiveOnly.length} ArtDmx source(s) via passive listening:`)
          for (const src of passiveOnly) {
            const unis = src.universes.map(u => `${u.net}.${u.sub}.${u.uni}`).join(', ')
            report(`  ${src.ip} — ${src.universes.length} universe(s): ${unis} (${src.packetCount} packets)`)
          }
        }
      }

      // (LLRP broadcast probes already sent at start of scan — see above)

      const totalNodes = (scanArtNet ? this.nodes.size : 0) +
                         (scanSACN ? this.sacnSources.size : 0) +
                         (scanArtNet ? this.dmxSources.size : 0)
      report(`Scan complete — ${totalNodes} node(s), ${allDevices.length} RDM device(s) found.`, { done: true })
      return allDevices

    } finally {
      this.running = false
    }
  }

  // ─── Network Diagnostics ─────────────────────────────────────────────────────

  /**
   * ICMP ping a host.  Returns true if the host responded, false if unreachable
   * or if ping timed out.  Uses the OS `ping` command.
   */
  _pingHost(ip) {
    return new Promise((resolve) => {
      // NOTE: -W semantics differ by OS:
      //   macOS: -W <waittime_ms>   → -W 2000 = 2 seconds
      //   Linux: -W <waittime_s>    → -W 2    = 2 seconds
      //   Windows: -w <waittime_ms> → -w 2000 = 2 seconds
      let cmd
      if (process.platform === 'win32') {
        cmd = `ping -n 1 -w 2000 ${ip}`
      } else if (process.platform === 'darwin') {
        cmd = `ping -c 1 -W 2000 ${ip}`   // macOS: -W in ms
      } else {
        cmd = `ping -c 1 -W 2 ${ip}`      // Linux: -W in s
      }
      exec(cmd, (err) => resolve(!err))
    })
  }

  // ─── MAC Address Lookup ──────────────────────────────────────────────────────

  /**
   * Look up the MAC address of a host via ARP table.
   * Attempts a ping first to populate the ARP cache, then reads the ARP entry.
   * Returns { mac, vendor } or null if lookup fails.
   *
   * Known vendor OUI prefixes (first 3 bytes of MAC):
   *   00:04:a1  = Pathway Connectivity (Pathport devices)
   *   00:50:45  = MA Lighting (grandMA consoles)
   *   00:1c:c0  = MA Lighting (grandMA2/3 newer)
   *   d8:80:83  = MA Lighting (grandMA3)
   */
  async _lookupMAC(ip) {
    // Known OUI → vendor map
    const OUI_MAP = {
      '00:04:a1': 'Pathway',
      '00:50:45': 'MA Lighting',
      '00:1c:c0': 'MA Lighting',
      'd8:80:83': 'MA Lighting',
      '3c:a3:08': 'MA Lighting',
      '00:20:40': 'ETC',
      '00:a0:57': 'ETC',
    }

    return new Promise((resolve) => {
      // Ping to ensure ARP cache is populated, then read ARP table.
      // NOTE: The caller already ran _pingHost() before this, so the ARP cache
      // is likely already populated. We still ping here as a safety net.
      // Platform notes:
      //   macOS: -W is in milliseconds; -n is NOT a valid flag for arp on macOS
      //   Linux: -W is in seconds; arp -n suppresses hostname resolution
      //   Windows: arp -a lists all, grep isn't available
      let arpCmd
      if (process.platform === 'win32') {
        arpCmd = `ping -n 1 -w 500 ${ip} >nul 2>&1 & arp -a ${ip}`
      } else if (process.platform === 'darwin') {
        arpCmd = `ping -c 1 -W 1000 ${ip} >/dev/null 2>&1 ; arp ${ip} 2>/dev/null`
      } else {
        arpCmd = `ping -c 1 -W 1 ${ip} >/dev/null 2>&1 ; arp -n ${ip} 2>/dev/null || arp ${ip} 2>/dev/null`
      }

      exec(arpCmd, { timeout: 4000 }, (err, stdout) => {
        if (err || !stdout) return resolve(null)

        // Parse MAC from ARP output — works on macOS, Linux, and Windows.
        // IMPORTANT: macOS arp outputs short-form MACs without zero-padding:
        //   macOS:  "? (192.168.1.39) at 0:4:a1:xx:xx:xx on en0 ..."  ← 1-2 hex digits per segment
        //   Linux:  "192.168.1.39  ether  00:04:a1:xx:xx:xx  C  en0"   ← always 2 hex digits
        //   Win:    "  192.168.1.39    00-04-a1-xx-xx-xx    dynamic"    ← dash-separated
        // The regex accepts 1-2 hex digits per segment; we zero-pad afterwards.
        const macMatch = stdout.match(/([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2}/)
        if (!macMatch) return resolve(null)

        // Normalize to zero-padded, colon-separated form: "00:04:a1:xx:xx:xx"
        const mac = macMatch[0].toLowerCase()
          .replace(/-/g, ':')
          .split(':')
          .map(s => s.padStart(2, '0'))
          .join(':')
        const oui = mac.slice(0, 8)  // "00:04:a1"
        const vendor = OUI_MAP[oui] || 'Unknown'

        resolve({ mac, vendor })
      })
    })
  }

  // ─── UID Math ──────────────────────────────────────────────────────────────────

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

/**
 * Return local IPv4 addresses that are on the same Class-A /8 subnet as the
 * given IP (e.g. if nodeIP is 10.30.142.39, returns all local 10.x.x.x IPs).
 * This is used to find Pathscape running on the same machine, since Pathport
 * nodes are RDMnet components that connect TO a Pathscape broker — the broker
 * listens on the local machine, not on the node IP.
 */
function _getLocalIPsOnSameOctet(nodeIP) {
  const nodeOctet = parseInt((nodeIP || '').split('.')[0], 10)
  if (!nodeOctet) return []
  const result = []
  const ifaces = os.networkInterfaces()
  for (const addrs of Object.values(ifaces)) {
    for (const addr of (addrs || [])) {
      if (addr.family === 'IPv4' && !addr.internal) {
        const localOctet = parseInt(addr.address.split('.')[0], 10)
        if (localOctet === nodeOctet) result.push(addr.address)
      }
    }
  }
  return [...new Set(result)]
}

/** Return all non-loopback IPv4 addresses on this machine. */
function _getAllLocalIPs() {
  const result = []
  const ifaces = os.networkInterfaces()
  for (const addrs of Object.values(ifaces)) {
    for (const addr of (addrs || [])) {
      if (addr.family === 'IPv4' && !addr.internal) {
        result.push(addr.address)
      }
    }
  }
  return [...new Set(result)]
}

const RDMNET_PORT = 5569

module.exports = Scanner
