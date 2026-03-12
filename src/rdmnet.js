/**
 * rdmnet.js
 * E1.33 RDMnet probe and discovery.
 *
 * Implements:
 *  1. LLRP (Low Level Recovery Protocol) UDP broadcast probe on port 5569
 *  2. TCP connection probe to port 5569 (broker detection)
 *  3. mDNS discovery for _rdmnet._tcp.local services
 *  4. Simplified RPT (RDM Packet Transport) for sending RDM commands through a broker
 *
 * E1.33 / RDMnet Quick Reference:
 *   - UDP port 5569 — LLRP discovery (broadcast probe → unicast reply)
 *   - TCP port 5569 — Broker connections (controller connects to broker)
 *   - mDNS service type: _rdmnet._tcp.local
 *
 * PDU Layer structure (all lengths are big-endian, flags field includes length):
 *   Flags+Length (2 bytes, top 4 bits = 0x7, bottom 12 = body length including this field)
 *   Vector       (N bytes, depends on layer)
 *   Header       (N bytes, depends on layer)
 *   Data         (N bytes, PDU payload)
 *
 * Root Layer Vector for RDMnet: 0x00000003 (VECTOR_ROOT_BROKER)
 *                                0x00000004 (VECTOR_ROOT_RPT)
 *                                0x00000005 (VECTOR_ROOT_EPT)
 */

'use strict'

const dgram        = require('dgram')
const net          = require('net')
const EventEmitter = require('events')
const os           = require('os')

const RDMNET_PORT   = 5569
const LLRP_MULTICAST = '239.255.250.133'  // E1.33 LLRP multicast address (informational)

// Root-layer vectors
const VECTOR_ROOT_LLRP       = 0x00000008
const VECTOR_ROOT_BROKER     = 0x00000003
const VECTOR_ROOT_RPT        = 0x00000004

// LLRP vectors
const VECTOR_LLRP_PROBE_REQUEST  = 0x00000001
const VECTOR_LLRP_PROBE_REPLY    = 0x00000002
const VECTOR_LLRP_RDM_CMD        = 0x00000003

// RPT vectors
const VECTOR_RPT_REQUEST  = 0x00000001
const VECTOR_RPT_STATUS   = 0x00000002
const VECTOR_RPT_NOTIFICATION = 0x00000003

// RDM inside LLRP vector
const VECTOR_RDM_CMD_RD_DATA = 0x01

// Connection state
const CONN_IDLE         = 'idle'
const CONN_CONNECTING   = 'connecting'
const CONN_CONNECTED    = 'connected'
const CONN_DISCONNECTED = 'disconnected'

// CID (Component Identifier) — 16-byte UUID for this controller instance
// We generate one from the MAC address + random bytes
function makeCID() {
  const buf = Buffer.alloc(16)
  // RFC 4122 v4 UUID-like: random bytes with version/variant bits set
  for (let i = 0; i < 16; i++) buf[i] = Math.floor(Math.random() * 256)
  buf[6] = (buf[6] & 0x0f) | 0x40  // version 4
  buf[8] = (buf[8] & 0x3f) | 0x80  // variant 10
  return buf
}

// ─── PDU helpers ─────────────────────────────────────────────────────────────

/**
 * Build the ACN/RDMnet flags+length field.
 * Flags: 0x7000 (top nibble = 7 = "inherited length, vector present, header present")
 * Length: 12-bit value of the entire PDU including this 2-byte header.
 */
function flagsAndLength(bodyLen) {
  const total = bodyLen + 2  // +2 for the flags+length field itself
  const hi = 0x70 | ((total >> 8) & 0x0F)
  const lo = total & 0xFF
  return [hi, lo]
}

/**
 * Assemble a preamble-less ACN PDU block.
 * @param {number}   vectorU32  - 4-byte big-endian vector
 * @param {Buffer}   header     - PDU header bytes
 * @param {Buffer}   data       - PDU data (child PDUs or payload)
 */
function buildPDU(vectorU32, header, data) {
  const body = Buffer.alloc(4 + header.length + data.length)
  body.writeUInt32BE(vectorU32, 0)
  header.copy(body, 4)
  data.copy(body, 4 + header.length)
  const [flHi, flLo] = flagsAndLength(body.length)
  const out = Buffer.alloc(2 + body.length)
  out[0] = flHi
  out[1] = flLo
  body.copy(out, 2)
  return out
}

// ─── RDMnet Preamble ──────────────────────────────────────────────────────────

/**
 * E1.17 ACN preamble (16 bytes) used for all UDP-based RDMnet packets.
 * Magic bytes: 0x0010 (preamble size) + 0x0000 (postamble size) + 4-byte ACN PID
 */
function buildUDPPreamble() {
  const pre = Buffer.alloc(16)
  pre.writeUInt16BE(0x0010, 0)  // preamble size
  pre.writeUInt16BE(0x0000, 2)  // postamble size
  // ACN Packet Identifier: 0x41 0x53 0x43 0x2d 0x45 0x31 0x2e 0x31 0x37 0x00 0x00 0x00
  Buffer.from('4153432d45312e313700000000000000', 'hex').copy(pre, 4)
  return pre.slice(0, 16)
}

// The ACN Packet Identifier (12 bytes)
const ACN_PID = Buffer.from('4153432d45312e313700000000000000', 'hex').slice(0, 12)

// ─── LLRP Probe Request ───────────────────────────────────────────────────────

/**
 * Build an E1.33 LLRP Probe Request PDU.
 * Sent via UDP broadcast to discover RDMnet brokers and devices.
 *
 * Structure:
 *   ACN Preamble (16 bytes)
 *   Root PDU:
 *     Flags+Length
 *     Vector = VECTOR_ROOT_LLRP (0x00000008)
 *     CID (16 bytes)
 *     LLRP PDU:
 *       Flags+Length
 *       Vector = VECTOR_LLRP_PROBE_REQUEST (0x00000001)
 *       [no header for probe request]
 *       Probe Request PDU:
 *         Lower UID (6 bytes) = 0x0000 0x0000 0x0000
 *         Upper UID (6 bytes) = 0xFFFF 0xFFFF 0xFFFF
 *         Filter (2 bytes)    = 0x0001 (include brokers) | 0x0002 (include devices)
 *         [Known UIDs TLV omitted]
 */
function buildLLRPProbeRequest(cid) {
  // Probe request payload: lower UID, upper UID, filter
  const prPayload = Buffer.alloc(14)
  // Lower UID: all zeros
  prPayload.fill(0x00, 0, 6)
  // Upper UID: all 0xFF
  prPayload.fill(0xFF, 6, 12)
  // Filter: 0x0003 = BROKERS | DEVICES
  prPayload.writeUInt16BE(0x0003, 12)

  const llrpPDU  = buildPDU(VECTOR_LLRP_PROBE_REQUEST, Buffer.alloc(0), prPayload)
  const rootPDU  = buildPDU(VECTOR_ROOT_LLRP, cid, llrpPDU)

  const pre = Buffer.alloc(16)
  pre.writeUInt16BE(0x0010, 0)  // preamble size
  pre.writeUInt16BE(0x0000, 2)  // postamble size
  ACN_PID.copy(pre, 4)

  return Buffer.concat([pre, rootPDU])
}

// ─── Parse incoming packets ───────────────────────────────────────────────────

/**
 * Parse an ACN/RDMnet packet (UDP or TCP frame).
 * Returns an object describing the packet, or null if unrecognised.
 */
function parseACNPacket(buf) {
  try {
  // Must have at least the preamble (16 bytes)
  if (buf.length < 16) return null

  // Validate ACN Packet Identifier at offset 4
  const pid = buf.slice(4, 16)
  if (!pid.equals(ACN_PID)) return null

  // Root PDU starts at offset 16
  // Need at least 22 bytes: 16 preamble + 2 flags/len + 4 vector
  if (buf.length < 22) return null
  const rootLen   = ((buf[16] & 0x0F) << 8) | buf[17]
  if (buf.length < 16 + rootLen) return null

  const rootVec   = buf.readUInt32BE(18)
  const rootCID   = buf.slice(22, 38)
  const childBuf  = buf.slice(38, 16 + rootLen)

  const result = {
    rootVector: rootVec,
    cid: rootCID.toString('hex'),
    children: [],
  }

  // Parse LLRP layer
  if (rootVec === VECTOR_ROOT_LLRP && childBuf.length >= 6) {
    const llrpLen = ((childBuf[0] & 0x0F) << 8) | childBuf[1]
    const llrpVec = childBuf.readUInt32BE(2)
    const llrpData = childBuf.slice(6, llrpLen)

    result.llrpVector = llrpVec

    if (llrpVec === VECTOR_LLRP_PROBE_REPLY && llrpData.length >= 6) {
      // Probe reply: UID (6 bytes) + hardware address (6 bytes)
      result.type = 'llrp_probe_reply'
      result.uid  = llrpData.slice(0, 6).toString('hex').toUpperCase()
      result.uidStr = `${result.uid.slice(0,4)}:${result.uid.slice(4)}`
      if (llrpData.length >= 12) {
        result.hwAddr = llrpData.slice(6, 12).toString('hex').match(/../g).join(':')
      }
    } else if (llrpVec === VECTOR_LLRP_PROBE_REQUEST) {
      result.type = 'llrp_probe_request'
    } else if (llrpVec === VECTOR_LLRP_RDM_CMD) {
      result.type = 'llrp_rdm_cmd'
      result.rdmData = llrpData.slice(1) // skip the sub-vector byte
    }
  }

  return result
  } catch (_) { return null }
}

// ─── TCP frame handling ───────────────────────────────────────────────────────

/**
 * Parse TCP stream data.  RDMnet TCP frames use a 16-byte preamble prefix.
 * Returns array of parsed packets; any remainder stays in the accumulator.
 */
function parseTCPStream(buf) {
  try {
    const packets = []
    let offset = 0

    while (offset < buf.length) {
      if (offset + 16 > buf.length) break

      // Check ACN PID
      const pid = buf.slice(offset + 4, offset + 16)
      if (!pid.equals(ACN_PID)) {
        offset++
        continue
      }

      if (offset + 22 > buf.length) break
      const rootLen = ((buf[offset + 16] & 0x0F) << 8) | buf[offset + 17]
      const total = 16 + rootLen
      if (total < 2 || offset + total > buf.length) { offset++; continue }

      const pkt = parseACNPacket(buf.slice(offset, offset + total))
      if (pkt) packets.push(pkt)
      offset += total
    }

    return { packets, remainder: buf.slice(offset) }
  } catch (_) {
    return { packets: [], remainder: Buffer.alloc(0) }
  }
}

// ─── RDMnet class ─────────────────────────────────────────────────────────────

class RDMnet extends EventEmitter {
  constructor() {
    super()
    this.cid         = makeCID()
    this.socket      = null   // UDP for LLRP
    this.tcpSockets  = new Map()  // ip → { socket, state, buf }
    this._brokers    = new Map()  // ip → broker info
  }

  // ─── LLRP UDP Probe ────────────────────────────────────────────────────────

  /**
   * Open UDP socket and start listening for LLRP responses.
   * @returns {Promise<void>}
   */
  startUDP() {
    return new Promise((resolve, reject) => {
      if (this.socket) return resolve()

      this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })

      this.socket.on('message', (msg, rinfo) => {
        const pkt = parseACNPacket(msg)
        if (!pkt) return

        if (pkt.type === 'llrp_probe_reply') {
          this.emit('llrpReply', { ip: rinfo.address, ...pkt })
        }
      })

      this.socket.on('error', (err) => {
        // Only emit if someone is listening — otherwise swallow to prevent crash
        if (this.listenerCount('error') > 0) this.emit('error', err)
      })

      this.socket.bind(0, '0.0.0.0', () => {
        try { this.socket.setBroadcast(true) } catch (_) {}
        resolve()
      })
    })
  }

  stopUDP() {
    if (this.socket) {
      try { this.socket.close() } catch (_) {}
      this.socket = null
    }
  }

  /**
   * Send an LLRP Probe Request to a unicast IP or broadcast address.
   * @param {string} address - Destination IP or broadcast
   */
  sendLLRPProbe(address) {
    if (!this.socket) return
    const pkt = buildLLRPProbeRequest(this.cid)
    this.socket.send(pkt, 0, pkt.length, RDMNET_PORT, address, () => {})
  }

  // ─── TCP Broker Probe ──────────────────────────────────────────────────────

  /**
   * Attempt a TCP connection to port 5569 on the given IP.
   * Resolves with { connected: true, data: Buffer|null } on success,
   * or { connected: false } on failure.
   * @param {string} ip
   * @param {number} [timeoutMs=2000]
   */
  probeTCP(ip, timeoutMs = 2000) {
    return new Promise((resolve) => {
      const sock = new net.Socket()
      let rxBuf = Buffer.alloc(0)
      let done  = false

      const finish = (result) => {
        if (done) return
        done = true
        clearTimeout(timer)
        try { sock.destroy() } catch (_) {}
        resolve(result)
      }

      const timer = setTimeout(() => finish({ connected: false, reason: 'timeout' }), timeoutMs)

      sock.connect(RDMNET_PORT, ip, () => {
        // Connection established — wait briefly for banner data
        setTimeout(() => {
          finish({
            connected: true,
            data: rxBuf.length > 0 ? rxBuf : null,
            parsedPkts: rxBuf.length > 0 ? parseTCPStream(rxBuf).packets : [],
          })
        }, 300)
      })

      sock.on('data', (chunk) => {
        rxBuf = Buffer.concat([rxBuf, chunk])
      })

      sock.on('error', () => finish({ connected: false, reason: 'refused' }))
      sock.on('close', () => finish({ connected: false, reason: 'closed' }))
    })
  }

  // ─── mDNS Discovery ───────────────────────────────────────────────────────

  /**
   * Listen for mDNS announcements of _rdmnet._tcp.local services.
   * Uses raw multicast UDP since we don't have the 'mdns' or 'multicast-dns'
   * npm packages.  Sends a DNS-SD query and collects responses.
   *
   * @param {number} [listenMs=3000] - How long to listen
   * @returns {Promise<Array>}        - Array of { name, ip, port, txt } objects
   */
  discoverMDNS(listenMs = 2000) {
    const MDNS_ADDR = '224.0.0.251'
    const MDNS_PORT = 5353
    const found     = new Map()

    // Hard deadline — resolves no matter what
    const deadline = new Promise((resolve) => setTimeout(() => resolve([]), listenMs + 500))

    const attempt = new Promise((resolve) => {
      let settled = false
      const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true })

      const cleanup = (result = []) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        clearTimeout(bindTimeout)
        sock.removeAllListeners()
        // MUST add a no-op error handler BEFORE close().
        // sock.close() on a socket that never finished binding emits an 'error'
        // event asynchronously on the next tick.  With all listeners removed it
        // would throw "Unhandled error event" → uncaughtException → crash.
        sock.on('error', () => {})
        try { sock.close() } catch (_) {}
        resolve(result)
      }

      // Hard timeout — fires even if bind callback never fires
      const timer      = setTimeout(() => cleanup(Array.from(found.values())), listenMs)
      // Bail out if bind takes more than 1 s (port 5353 held by mDNSResponder on macOS)
      const bindTimeout = setTimeout(() => cleanup([]), 1000)

      sock.on('error', () => cleanup([]))

      sock.bind({ port: MDNS_PORT, address: '0.0.0.0', exclusive: false }, () => {
        clearTimeout(bindTimeout)  // bind succeeded

        try { sock.addMembership(MDNS_ADDR) } catch (_) {}
        try { sock.setMulticastTTL(255) }     catch (_) {}

        // Build a DNS-SD query for PTR _rdmnet._tcp.local
        const query = buildMDNSQuery('_rdmnet._tcp.local')
        try { sock.send(query, 0, query.length, MDNS_PORT, MDNS_ADDR, () => {}) } catch (_) {}
        setTimeout(() => {
          try { sock.send(query, 0, query.length, MDNS_PORT, MDNS_ADDR, () => {}) } catch (_) {}
        }, 400)
      })

      sock.on('message', (msg, rinfo) => {
        // MUST be wrapped in try/catch — this is a socket event handler.
        // Any uncaught throw here becomes an uncaughtException → crash.
        // (Promise try/catch does NOT protect event handler callbacks.)
        try {
          const parsed = parseMDNSResponse(msg)
          if (!parsed) return

          const allRecords = parsed.answers.concat(parsed.additionals || [])

          // First pass: collect service instance names from _rdmnet._tcp PTR records ONLY.
          // We must NOT create entries for arbitrary A records — macOS mDNS floods us
          // with its entire cache (Apple TVs, printers, MacBooks) when we send a query,
          // and every .local hostname would falsely appear as an RDMnet device.
          for (const record of allRecords) {
            if (record.type === 'PTR' && record.name && record.name.includes('_rdmnet._tcp')) {
              const svcName = record.data
              if (svcName && !found.has(svcName)) {
                found.set(svcName, { name: svcName, ip: rinfo.address, port: RDMNET_PORT, _srvTarget: null })
              }
            }
          }

          // Second pass: enrich known _rdmnet service instances with SRV/A data.
          // SRV records: record.name = service instance name → extract target hostname + port.
          // A records:   record.name = hostname (e.g. "pathscape.local") — does NOT match
          //              service instance names, so we track the SRV target and use it to
          //              resolve A records.
          const srvTargets = new Map()  // hostname → [service instance names]
          for (const record of allRecords) {
            if (record.type === 'SRV' && found.has(record.name)) {
              const entry = found.get(record.name)
              // record.data may be undefined for malformed SRV records (rdlen < 6)
              if (!record.data) continue
              entry.port = record.data.port
              if (!entry.ip) entry.ip = rinfo.address
              // Store the SRV target hostname so we can look it up in A records
              const target = record.data.target
              if (target) {
                entry._srvTarget = target
                if (!srvTargets.has(target)) srvTargets.set(target, [])
                srvTargets.get(target).push(record.name)
              }
            }
          }
          // Now use A records to resolve the SRV targets to actual IP addresses
          for (const record of allRecords) {
            if (record.type === 'A' && srvTargets.has(record.name)) {
              for (const svcName of srvTargets.get(record.name)) {
                if (found.has(svcName)) {
                  found.get(svcName).ip = record.data
                }
              }
            }
          }
        } catch (_) {
          // Swallow — malformed mDNS packet or unexpected record structure.
          // Crashing the entire scan over a bad DNS packet is not acceptable.
        }
      })
    })

    // Race: whichever resolves first (attempt or hard deadline).
    // Strip internal bookkeeping fields (_srvTarget) before returning.
    return Promise.race([attempt, deadline]).then(results =>
      results.map(({ _srvTarget, ...rest }) => rest)
    )
  }

  // ─── High-level probe ─────────────────────────────────────────────────────

  /**
   * Probe a single IP for RDMnet support.
   *
   * Strategy:
   *   1. TCP connect to port 5569 — if it succeeds, the node is running an RDMnet broker.
   *   2. Send 3× LLRP UDP probe requests (unicast) and listen for replies.
   *
   * @param {string} ip
   * @param {Function} report - progress callback(msg)
   * @param {number}   [listenMs=2000]
   * @returns {Promise<{tcpConnected, llrpReplies, brokerData}>}
   */
  probeIP(ip, report, listenMs = 2000) {
    // Hard outer timeout — probeIP can NEVER exceed this no matter what
    const HARD_LIMIT_MS = listenMs + 5000
    const deadline = new Promise(r =>
      setTimeout(() => r({ ip, tcpConnected: false, llrpReplies: [], brokerData: null, timedOut: true }), HARD_LIMIT_MS)
    )
    return Promise.race([this._doProbeIP(ip, report, listenMs), deadline])
  }

  async _doProbeIP(ip, report, listenMs) {
    const result = { ip, tcpConnected: false, llrpReplies: [], brokerData: null }

    // ─ TCP probe ─
    report(`  [RDMnet] TCP probe → ${ip}:${RDMNET_PORT}…`)
    let tcpResult
    try {
      tcpResult = await this.probeTCP(ip, 2000)
    } catch (_) {
      tcpResult = { connected: false, reason: 'error' }
    }

    if (tcpResult.connected) {
      result.tcpConnected = true
      result.brokerData   = tcpResult.data
      report(`  [RDMnet] ✓ TCP connected to ${ip}:${RDMNET_PORT} — RDMnet broker detected!`)
      if (tcpResult.parsedPkts && tcpResult.parsedPkts.length > 0) {
        report(`  [RDMnet]   Received ${tcpResult.parsedPkts.length} PDU(s) on connect.`)
      }
    } else {
      report(`  [RDMnet] TCP port ${RDMNET_PORT} not open on ${ip} (${tcpResult.reason || 'no reply'})`)
    }

    // ─ LLRP UDP probe ─
    report(`  [RDMnet] Sending LLRP UDP probes → ${ip}…`)
    let replies = []
    try {
      replies = await this._probeLLRP(ip, listenMs)
    } catch (_) {}
    result.llrpReplies = replies

    if (replies.length > 0) {
      report(`  [RDMnet] ✓ LLRP Probe Reply from ${ip}:`)
      for (const r of replies) {
        report(`    UID: ${r.uidStr}  HW: ${r.hwAddr || 'unknown'}  CID: ${r.cid}`)
      }
    } else {
      report(`  [RDMnet] No LLRP probe replies from ${ip}.`)
    }

    return result
  }

  async _probeLLRP(ip, listenMs) {
    const replies = []

    try { await this.startUDP() } catch (_) { return replies }

    const handler = (reply) => {
      if (reply.ip === ip) replies.push(reply)
    }
    this.on('llrpReply', handler)

    // Send probe 3 times to handle packet loss
    this.sendLLRPProbe(ip)
    await _delay(200)
    this.sendLLRPProbe(ip)
    await _delay(200)
    this.sendLLRPProbe(ip)

    await _delay(listenMs - 400)

    this.off('llrpReply', handler)

    return replies
  }

  // ─── Broadcast LLRP sweep ────────────────────────────────────────────────

  /**
   * Broadcast LLRP probe on all local subnets for the given listen period.
   * @param {number} [listenMs=3000]
   * @returns {Promise<Array>} - Array of LLRP replies
   */
  async broadcastProbe(listenMs = 3000) {
    const replies = []
    const seen    = new Set()

    await this.startUDP()

    const handler = (reply) => {
      if (!seen.has(reply.ip)) {
        seen.add(reply.ip)
        replies.push(reply)
      }
    }
    this.on('llrpReply', handler)

    // Broadcast on all local subnets
    const broadcasts = getLocalBroadcasts()
    for (const bc of broadcasts) {
      this.sendLLRPProbe(bc)
    }
    this.sendLLRPProbe('255.255.255.255')

    await _delay(listenMs / 2)

    for (const bc of broadcasts) this.sendLLRPProbe(bc)
    this.sendLLRPProbe('255.255.255.255')

    await _delay(listenMs / 2)

    this.off('llrpReply', handler)
    this.stopUDP()

    return replies
  }

  destroy() {
    this.stopUDP()
    for (const { socket } of this.tcpSockets.values()) {
      try { socket.destroy() } catch (_) {}
    }
    this.tcpSockets.clear()
  }
}

// ─── mDNS helpers ─────────────────────────────────────────────────────────────

function buildMDNSQuery(name) {
  // Build a minimal DNS query packet for PTR record
  const buf = Buffer.alloc(512)
  let off = 0

  buf.writeUInt16BE(0x0000, off); off += 2  // Transaction ID (0 for mDNS)
  buf.writeUInt16BE(0x0000, off); off += 2  // Flags: Standard Query
  buf.writeUInt16BE(0x0001, off); off += 2  // QDCOUNT: 1
  buf.writeUInt16BE(0x0000, off); off += 2  // ANCOUNT: 0
  buf.writeUInt16BE(0x0000, off); off += 2  // NSCOUNT: 0
  buf.writeUInt16BE(0x0000, off); off += 2  // ARCOUNT: 0

  // Encode QNAME
  for (const label of name.split('.')) {
    buf[off++] = label.length
    buf.write(label, off, 'ascii')
    off += label.length
  }
  buf[off++] = 0x00  // Root label

  buf.writeUInt16BE(0x000C, off); off += 2  // QTYPE: PTR
  buf.writeUInt16BE(0x0001, off); off += 2  // QCLASS: IN

  return buf.slice(0, off)
}

function parseMDNSResponse(buf) {
  if (buf.length < 12) return null
  try {
    let off = 0
    /* const txid = */ buf.readUInt16BE(off); off += 2
    const flags   = buf.readUInt16BE(off); off += 2
    const qdcount = buf.readUInt16BE(off); off += 2
    const ancount = buf.readUInt16BE(off); off += 2
    /* const nscount = */ buf.readUInt16BE(off); off += 2
    const arcount = buf.readUInt16BE(off); off += 2

    if (!(flags & 0x8000)) return null  // Not a response

    // Skip questions
    for (let i = 0; i < qdcount; i++) {
      const { end } = readDNSName(buf, off)
      off = end + 4
    }

    const answers     = readDNSRecords(buf, off, ancount)
    off = answers.endOffset
    const additionals = readDNSRecords(buf, off, arcount)

    return { answers: answers.records, additionals: additionals.records }
  } catch (_) {
    return null
  }
}

function readDNSName(buf, off) {
  let name = ''
  let jumped = false
  let returnOff = off
  let hops = 0  // guard against circular compression pointers

  while (off < buf.length) {
    // DNS names are max 253 chars / ~128 labels. If we've followed more than
    // 64 pointer hops it's a circular reference — bail out to avoid blocking
    // the event loop forever (infinite loop = frozen app = "crash").
    if (++hops > 64) break
    const len = buf[off]
    if (len === 0) { off++; break }
    if ((len & 0xC0) === 0xC0) {
      if (off + 1 >= buf.length) break  // truncated pointer
      if (!jumped) returnOff = off + 2
      off = ((len & 0x3F) << 8) | buf[off + 1]
      jumped = true
      continue
    }
    if (off + 1 + len > buf.length) break  // label extends past buffer
    if (name) name += '.'
    name += buf.slice(off + 1, off + 1 + len).toString('ascii')
    off += 1 + len
  }

  return { name, end: jumped ? returnOff : off }
}

function readDNSRecords(buf, off, count) {
  const records = []
  for (let i = 0; i < count; i++) {
    if (off >= buf.length) break
    const nameResult = readDNSName(buf, off)
    off = nameResult.end
    if (off + 10 > buf.length) break

    const type  = buf.readUInt16BE(off); off += 2
    /* const cls = */ buf.readUInt16BE(off); off += 2
    /* const ttl = */ buf.readUInt32BE(off); off += 4
    const rdlen = buf.readUInt16BE(off); off += 2
    const rdata = buf.slice(off, off + rdlen)
    off += rdlen

    const record = { name: nameResult.name, type: _dnsTypeName(type) }

    if (type === 1 && rdlen === 4) {
      // A record
      record.data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`
    } else if (type === 12) {
      // PTR record
      record.data = readDNSName(rdata, 0).name
    } else if (type === 33 && rdlen >= 6) {
      // SRV record
      record.data = {
        priority: rdata.readUInt16BE(0),
        weight:   rdata.readUInt16BE(2),
        port:     rdata.readUInt16BE(4),
        target:   readDNSName(rdata, 6).name,
      }
    } else if (type === 16) {
      // TXT record
      const txts = []
      let toff = 0
      while (toff < rdata.length) {
        const tlen = rdata[toff++]
        txts.push(rdata.slice(toff, toff + tlen).toString('utf8'))
        toff += tlen
      }
      record.data = txts
    }

    records.push(record)
  }
  return { records, endOffset: off }
}

function _dnsTypeName(n) {
  return { 1: 'A', 12: 'PTR', 28: 'AAAA', 33: 'SRV', 16: 'TXT' }[n] || `TYPE${n}`
}

// ─── Network helpers ──────────────────────────────────────────────────────────

function getLocalBroadcasts() {
  const bcs  = []
  const ifaces = os.networkInterfaces()
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal && iface.cidr) {
        const parts = iface.address.split('.')
        const maskParts = iface.netmask.split('.')
        const bc = parts.map((p, i) => (parseInt(p) | (~parseInt(maskParts[i]) & 0xFF))).join('.')
        bcs.push(bc)
      }
    }
  }
  return [...new Set(bcs)]
}

function _delay(ms) {
  return new Promise(r => setTimeout(r, ms))
}

module.exports = RDMnet
