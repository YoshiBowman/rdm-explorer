/**
 * scanner.js
 * Orchestrates Art-Net node discovery, sACN source discovery, and RDM device enumeration.
 * Emits events: nodeFound, deviceFound, progress, error
 */

'use strict'

const EventEmitter = require('events')
const { exec }     = require('child_process')
const ArtNet   = require('./artnet')
const SACN     = require('./sacn')
const RDM      = require('./rdm')
const RDMnet   = require('./rdmnet')

const POLL_WAIT_MS       = 2500   // Wait after ArtPoll for replies
const SACN_LISTEN_MS     = 3000   // Time to listen for sACN sources
const RDM_TIMEOUT_MS     = 400    // Timeout waiting for a single RDM response
const RDM_SET_TIMEOUT_MS = 600

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
    this.running = false
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
        // sACN may fail if port is in use — don't block the scan
        this.emit('error', new Error(`sACN start failed: ${err.message}`))
      }
    }
  }

  stop() {
    this.artnet.stop()
    this.sacn.stop()
    this.rdmnet.destroy()
    this.dmxSources.clear()
    this.running = false
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
        supportsRDM: true,
        protocol:    'artnet-manual',
        manual:      true,
      })
    }
  }

  // ─── Art-Net Node Discovery ─────────────────────────────────────────────────

  async discoverNodes() {
    this.nodes.clear()

    // Standard broadcast ArtPoll on all known subnets
    for (const bc of this.broadcasts) this.artnet.sendArtPoll(bc)

    // If a subnet override is set (e.g. "10.30.142"), unicast ArtPoll to every
    // host in that /24. This reaches nodes on remote subnets that don't receive
    // our broadcast (e.g. Pathport nodes on a dedicated lighting network).
    if (this.subnetOverride) {
      const parts = this.subnetOverride.split('.')
      if (parts.length === 3) {
        for (let h = 1; h <= 254; h++) {
          this.artnet.sendArtPoll(`${this.subnetOverride}.${h}`)
          if (h % 50 === 0) await this._delay(10)
        }
      }
    }

    await this._delay(800)
    for (const bc of this.broadcasts) this.artnet.sendArtPoll(bc)
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
    this.sacnSources.clear()
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

    const report = (msg, extra = {}) => {
      this.emit('progress', { message: msg, ...extra })
      if (onProgress) onProgress({ message: msg, ...extra })
    }

    try {
      const allDevices = []

      // ── mDNS RDMnet pre-scan (once, before per-node work) ─────────────────
      // Run this early so results are ready to display per-node without
      // re-querying the network 4 times.
      let mdnsRDMnetServices = []
      if (scanArtNet) {
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

      // ── Art-Net Discovery ──────────────────────────────────────────────────
      if (scanArtNet) {
        report(`Sending ArtPoll to: ${this.broadcasts.join(', ')}${this.subnetOverride ? ` + unicast sweep of ${this.subnetOverride}.1–254` : ''}`)
        report('Searching for Art-Net nodes on the network…')
        const nodes = await this.discoverNodes()

        if (nodes.length === 0) {
          report('No Art-Net nodes found.')
        } else {
          report(`Found ${nodes.length} Art-Net node(s). Starting RDM discovery…`, { nodes })

          for (const node of nodes) {
            report(`Scanning node: ${node.shortName} (${node.ip})`)

            // ── Connectivity pre-check for manually added nodes ──────────────
            // Manually added nodes never respond to ArtPoll so we can't confirm
            // connectivity that way.  A quick ICMP ping tells us whether IP-level
            // traffic can actually reach the node before spending time on RDM.
            if (node.manual) {
              report(`  [ping] Checking connectivity to ${node.ip}…`)
              const reachable = await this._pingHost(node.ip)
              if (reachable) {
                report(`  [ping] ${node.ip} is reachable ✓`)
              } else {
                report(`  [ping] WARNING: ${node.ip} did not respond to ping — node is not`)
                report(`         reachable from this machine.  Skipping RDM scan for this node.`)
                report(`         FIX: Make sure this Mac has a NIC configured on the same subnet`)
                report(`         as the node.  Open System Settings → Network, add an IP like`)
                report(`         10.30.142.250/8 to the ethernet interface, then scan again.`)
                report(`         (Pathscape reaches nodes via its own proprietary discovery,`)
                report(`          which may not require standard IP routing.)`)
                continue  // no point sending Art-Net into the void
              }
            }

            if (!node.supportsRDM) {
              report(`  ${node.shortName} does not support RDM — skipping RDM scan.`)
              continue
            }

            const universesToScan = node.universes.length > 0
              ? node.universes
              : [{ net: 0, sub: 0, uni: 0 }]

            let nodeFoundAnyDevices = false

            // Start watching ALL raw UDP packets from this node so we can report
            // whether it sends ANYTHING back (even non-Art-Net protocol packets).
            if (node.manual) this.artnet.watchIP(node.ip)

            for (const uniInfo of universesToScan) {
              const uniLabel = `${uniInfo.net}.${uniInfo.sub}.${uniInfo.uni}`
              report(`  Discovering RDM on universe ${uniLabel} → sending to ${node.ip}:6454`)

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

              nodeFoundAnyDevices = true
              report(`  Found ${uids.length} RDM UID(s) on universe ${uniLabel}. Reading device info…`)

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
                  allDevices.push(deviceInfo)
                  this.emit('deviceFound', deviceInfo)
                } catch (e) {
                  report(`    Error reading ${uidStr}: ${e.message}`)
                }
              }
            }

            // ── Raw-packet diagnostic ───────────────────────────────────────────
            if (node.manual) {
              const watch = this.artnet.stopWatchIP()
              if (watch.count === 0) {
                report(`  [diag] ${node.ip} sent 0 packets back during entire scan.`)
                report(`         Node is silently ignoring Art-Net RDM (opCode 0x8002).`)
                report(`         → Probing for E1.33 RDMnet (TCP/UDP port 5569) and mDNS…`)

                // ── E1.33 RDMnet probe ──────────────────────────────────────────
                try {
                  const rdmnetResult = await this.rdmnet.probeIP(node.ip, report, 2000)

                  if (rdmnetResult.tcpConnected || rdmnetResult.llrpReplies.length > 0) {
                    report(`  [RDMnet] ✓ ${node.ip} supports E1.33 RDMnet!`)
                    report(`           RDM Explorer can now query RDM devices through this broker.`)
                  } else {
                    report(`  [RESULT] ${node.ip} is a Pathway Pathport node that does not support`)
                    report(`           Art-Net RDM or E1.33 RDMnet in its current firmware.`)
                    report(``)
                    report(`           Pathport nodes only expose RDM via E1.33 RDMnet, which`)
                    report(`           requires firmware v6.3.1 or newer.`)
                    report(``)
                    report(`           TO FIX: In Pathscape → Administration → check for firmware`)
                    report(`           updates and upgrade these nodes to v6.3.1+. Then in each`)
                    report(`           node's Properties panel, enable RDMnet and re-run this scan.`)
                  }

                  // Use the mDNS results already collected at scan start (no re-query)
                  if (mdnsRDMnetServices.length > 0) {
                    report(`  [RDMnet] RDMnet brokers found earlier via mDNS: ${mdnsRDMnetServices.map(s => s.ip).join(', ')}`)
                  }

                } catch (rdmnetErr) {
                  report(`  [RDMnet] Probe error: ${rdmnetErr.message}`)
                }

              } else {
                report(`  [diag] Received ${watch.count} packet(s) from ${node.ip} during scan:`)
                for (const s of watch.samples) {
                  const proto = s.isArtNet
                    ? `Art-Net opCode 0x${(s.opCode || 0).toString(16).toUpperCase().padStart(4, '0')}`
                    : `NON-Art-Net`
                  report(`    ${s.len} bytes  ${proto}  header: ${s.header}`)
                }
                if (watch.samples.some(s => !s.isArtNet)) {
                  report(`  [diag] ⚠ Non-Art-Net packets detected — node is responding with`)
                  report(`         a proprietary protocol. Copy this log and share it for analysis.`)
                }
              }
            }

            // Node was reachable but RDM returned nothing — give specific hints
            if (node.manual && !nodeFoundAnyDevices) {
              report(`  NOTE: No RDM devices found on ${node.shortName}.`)
            }
          }
        }
      }

      // ── sACN Discovery ─────────────────────────────────────────────────────
      if (scanSACN) {
        report('Listening for sACN sources on the network…')
        const sources = await this.discoverSACNSources()

        if (sources.length === 0) {
          report('No sACN sources found.')
        } else {
          report(`Found ${sources.length} sACN source(s).`)
          for (const src of sources) {
            const uniList = src.universes.map(u => u.universe || u.uni).join(', ')
            report(`  ${src.shortName} (${src.ip}) — universes: ${uniList}`)
          }
        }
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

      // ── E1.33 RDMnet Broadcast Discovery ─────────────────────────────────
      // Send LLRP broadcast probes on all local subnets to catch any RDMnet
      // brokers that weren't found via Art-Net (e.g. Pathway LX Opto series).
      if (scanArtNet) {
        report('Sending E1.33 RDMnet LLRP broadcast probes…')
        try {
          const llrpFound = await this.rdmnet.broadcastProbe(2000)
          if (llrpFound.length > 0) {
            report(`Found ${llrpFound.length} RDMnet device(s) via LLRP broadcast:`)
            for (const r of llrpFound) {
              report(`  ${r.ip}  UID: ${r.uidStr || 'n/a'}  CID: ${r.cid || 'n/a'}`)
            }
          } else {
            report('No RDMnet devices found via LLRP broadcast.')
          }
        } catch (e) {
          report(`RDMnet broadcast probe error: ${e.message}`)
        }
      }

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
      // -c 1: send one packet  -W 1: wait 1 second (macOS/Linux)
      // Windows: -n 1 -w 1000
      const cmd = process.platform === 'win32'
        ? `ping -n 1 -w 1000 ${ip}`
        : `ping -c 1 -W 1 ${ip}`
      exec(cmd, (err) => resolve(!err))
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

module.exports = Scanner
