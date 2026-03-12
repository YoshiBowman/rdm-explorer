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
 * Root Layer Vector for RDMnet: 0x00000005 (VECTOR_ROOT_RPT)
 *                                0x00000009 (VECTOR_ROOT_BROKER)
 *                                0x0000000A (VECTOR_ROOT_LLRP)
 */

'use strict'

const dgram        = require('dgram')
const net          = require('net')
const EventEmitter = require('events')
const os           = require('os')

const RDMNET_PORT   = 5569
const LLRP_MULTICAST = '239.255.250.133'  // E1.33 LLRP multicast address

// LLRP Broadcast CID — used as Destination CID in LLRP Probe Requests
// to address all LLRP targets.  Per E1.33-2019 Section 5.3.
const LLRP_BROADCAST_CID = Buffer.from('fbad822cbd0c4d4cbdc87eabebc85aff', 'hex')

// Root-layer vectors (E1.33 Table A-3 — per Wireshark packet-acn.c / ANSI E1.33-2019)
// CRITICAL: these must NOT be confused with E1.31 sACN vectors
//   0x00000004 = sACN Data (E1.31), 0x00000008 = sACN Extended (E1.31)
const VECTOR_ROOT_LLRP       = 0x0000000A
const VECTOR_ROOT_RPT        = 0x00000005
const VECTOR_ROOT_BROKER     = 0x00000009

// LLRP vectors
const VECTOR_LLRP_PROBE_REQUEST  = 0x00000001
const VECTOR_LLRP_PROBE_REPLY    = 0x00000002
const VECTOR_LLRP_RDM_CMD        = 0x00000003

// LLRP Probe Request inner PDU vector (Table A-5)
const VECTOR_PROBE_REQUEST_DATA  = 0x00000001

// RPT vectors
const VECTOR_RPT_REQUEST  = 0x00000001
const VECTOR_RPT_STATUS   = 0x00000002
const VECTOR_RPT_NOTIFICATION = 0x00000003

// RDM inside LLRP vector
const VECTOR_RDM_CMD_RD_DATA = 0x01

// Broker vectors
const VECTOR_BROKER_CONNECT             = 0x00000001
const VECTOR_BROKER_CONNECT_REPLY       = 0x00000002
const VECTOR_BROKER_CLIENT_ENTRY_RPT    = 0x00000001
const VECTOR_BROKER_CONNECTED_CLIENT_LIST = 0x00000006
const VECTOR_BROKER_CLIENT_ADD          = 0x00000007
const VECTOR_BROKER_CLIENT_REMOVE       = 0x00000008
const VECTOR_BROKER_CLIENT_ENTRY_CHANGE = 0x00000009

// RPT request/notification sub-vectors
const VECTOR_REQUEST_RDM_CMD            = 0x00000001
const VECTOR_NOTIFICATION_RDM_CMD       = 0x00000001

// Broker Connect Reply status codes
const BROKER_OK               = 0x0000
const BROKER_SCOPE_NOT_FOUND  = 0x0001

// E1.33 protocol version
const E133_VERSION = 0x0001

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
 * Sent via UDP multicast/unicast to discover RDMnet devices and brokers.
 *
 * Per ANSI E1.33-2019 §5.4.2, the structure is TWO levels of PDU
 * nesting with the probe request fields directly in the LLRP data:
 *
 *   ACN Preamble (16 bytes)
 *   Root Layer PDU:
 *     Flags+Length (2)
 *     Vector = VECTOR_ROOT_LLRP (0x0000000A) (4 bytes)
 *     Header = CID (16 bytes) — sender Component Identifier
 *     └─ LLRP PDU:
 *          Flags+Length (2)
 *          Vector = VECTOR_LLRP_PROBE_REQUEST (0x00000001) (4 bytes)
 *          Header = Destination CID (16 bytes) — LLRP Broadcast CID
 *          Data:
 *            Lower UID (6 bytes)
 *            Upper UID (6 bytes)
 *            Filter (1 byte) — 0x01=client TCP inactive, 0x02=brokers only
 *            Known UIDs (variable, 0 entries for full range)
 *
 * NOTE: v0.2.3 tried 3-level nesting (wrapping data in a Probe Request
 * Data PDU with its own flags+length+vector).  This caused Pathport nodes
 * to briefly go offline — the extra PDU header bytes were misinterpreted
 * by the firmware.  Reverted to the simpler 2-level structure.
 *
 * Filter is 1 byte per the Wireshark dissector field definition
 * (hf_rdmnet_llrp_probe_request_filter uses FT_UINT8).
 */
function buildLLRPProbeRequest(cid) {
  // Probe request payload: lower UID(6) + upper UID(6) + filter(1) = 13 bytes
  const prPayload = Buffer.alloc(13)
  // Lower UID: all zeros (start of search range)
  prPayload.fill(0x00, 0, 6)
  // Upper UID: all 0xFF (end of search range — entire UID space)
  prPayload.fill(0xFF, 6, 12)
  // Filter: 0x03 = CLIENT_TCP_INACTIVE | BROKERS_ONLY (include everything)
  prPayload[12] = 0x03
  // No known UIDs appended — full discovery

  // LLRP PDU: header = Destination CID, data = probe fields (directly, no inner PDU)
  // For broadcast probes, Dest CID = LLRP Broadcast CID per E1.33-2019 §5.3.
  const llrpPDU  = buildPDU(VECTOR_LLRP_PROBE_REQUEST, LLRP_BROADCAST_CID, prPayload)

  // Root Layer PDU: header = our CID, data = LLRP PDU
  const rootPDU  = buildPDU(VECTOR_ROOT_LLRP, cid, llrpPDU)

  const pre = Buffer.alloc(16)
  pre.writeUInt16BE(0x0010, 0)  // preamble size
  pre.writeUInt16BE(0x0000, 2)  // postamble size
  ACN_PID.copy(pre, 4)

  return Buffer.concat([pre, rootPDU])
}

// ─── LLRP RDM Command ────────────────────────────────────────────────────────

/**
 * Build an LLRP RDM Command PDU.
 * Wraps a standard RDM packet inside LLRP for direct device communication
 * bypassing the broker.  Sent via UDP unicast to the target device.
 *
 * @param {Buffer} cid       - Our CID (16 bytes)
 * @param {Buffer} destCID   - Target device CID (16 bytes, from LLRP probe reply)
 * @param {Buffer} rdmPacket - Complete RDM packet (starting with 0xCC)
 */
function buildLLRPRdmCommand(cid, destCID, rdmPacket) {
  // LLRP layer: vector = RDM_CMD, header = destination CID, data = raw RDM packet
  // (2-level nesting — RDM packet goes directly in LLRP data, no inner PDU wrapper)
  const llrpPDU = buildPDU(VECTOR_LLRP_RDM_CMD, destCID, rdmPacket)
  const rootPDU = buildPDU(VECTOR_ROOT_LLRP, cid, llrpPDU)

  const pre = Buffer.alloc(16)
  pre.writeUInt16BE(0x0010, 0)
  pre.writeUInt16BE(0x0000, 2)
  ACN_PID.copy(pre, 4)

  return Buffer.concat([pre, rootPDU])
}

// ─── Broker Connect ──────────────────────────────────────────────────────────

/**
 * Build a Broker Connect message (sent over TCP to register as RPT Controller).
 *
 * Structure:
 *   Preamble (16 bytes)
 *   Root PDU (VECTOR_ROOT_BROKER, CID)
 *     Broker Connect PDU:
 *       Scope (63 bytes, UTF-8 null-padded, "default")
 *       E1.33 Version (2 bytes)
 *       Search Domain (231 bytes, null-padded)
 *       Connection Flags (1 byte)
 *       Client Entry PDU:
 *         CID (16) + UID (6) + Client Type (1) + Binding CID (16)
 *
 * @param {Buffer} cid - Our CID (16 bytes)
 * @param {Buffer} uid - Our controller UID (6 bytes)
 */
function buildBrokerConnect(cid, uid) {
  // Client Entry PDU data: CID + UID + ClientType + BindingCID
  const clientData = Buffer.alloc(39)
  cid.copy(clientData, 0)             // Client CID (16 bytes)
  uid.copy(clientData, 16)            // Client UID (6 bytes)
  clientData[22] = 0x01              // Client Type: RPT Controller
  // Binding CID: zeros (bytes 23-38) — only used by devices

  const clientEntry = buildPDU(VECTOR_BROKER_CLIENT_ENTRY_RPT, Buffer.alloc(0), clientData)

  // Broker Connect header: Scope(63) + Version(2) + SearchDomain(231) + Flags(1) = 297 bytes
  const connectHeader = Buffer.alloc(297)
  Buffer.from('default').copy(connectHeader, 0)    // Scope (null-terminated, padded)
  connectHeader.writeUInt16BE(E133_VERSION, 63)    // E1.33 Version
  // Search Domain (231 bytes): default = empty (all zeros)
  connectHeader[296] = 0x00                        // Connection Flags: 0 = none

  const brokerPDU = buildPDU(VECTOR_BROKER_CONNECT, connectHeader, clientEntry)
  const rootPDU   = buildPDU(VECTOR_ROOT_BROKER, cid, brokerPDU)

  const pre = Buffer.alloc(16)
  pre.writeUInt16BE(0x0010, 0)
  pre.writeUInt16BE(0x0000, 2)
  ACN_PID.copy(pre, 4)

  return Buffer.concat([pre, rootPDU])
}

// ─── RPT Request ─────────────────────────────────────────────────────────────

/**
 * Build an RPT Request PDU containing an RDM command.
 * Sent over TCP through a broker connection.
 *
 * @param {Buffer} cid          - Our CID (16 bytes)
 * @param {Buffer} srcUID       - Our controller UID (6 bytes)
 * @param {Buffer} destUID      - Target device UID (6 bytes)
 * @param {number} destEndpoint - Target endpoint (0 = device, 1+ = physical port)
 * @param {number} seqNum       - Sequence number (uint32)
 * @param {Buffer} rdmPacket    - Complete RDM packet
 */
function buildRPTRequest(cid, srcUID, destUID, destEndpoint, seqNum, rdmPacket) {
  // RPT header: srcUID(6) + srcEndpoint(2) + destUID(6) + destEndpoint(2) + seqNum(4) = 20 bytes
  const rptHeader = Buffer.alloc(20)
  srcUID.copy(rptHeader, 0)                      // Source UID
  rptHeader.writeUInt16BE(0, 6)                   // Source Endpoint (0 = controller)
  destUID.copy(rptHeader, 8)                      // Destination UID
  rptHeader.writeUInt16BE(destEndpoint, 14)       // Destination Endpoint
  rptHeader.writeUInt32BE(seqNum, 16)             // Sequence Number

  // RDM Command PDU (nested inside RPT Request)
  const rdmCmdPDU = buildPDU(VECTOR_REQUEST_RDM_CMD, Buffer.alloc(0), rdmPacket)

  const rptPDU  = buildPDU(VECTOR_RPT_REQUEST, rptHeader, rdmCmdPDU)
  const rootPDU = buildPDU(VECTOR_ROOT_RPT, cid, rptPDU)

  const pre = Buffer.alloc(16)
  pre.writeUInt16BE(0x0010, 0)
  pre.writeUInt16BE(0x0000, 2)
  ACN_PID.copy(pre, 4)

  return Buffer.concat([pre, rootPDU])
}

/**
 * Generate a 6-byte RDM UID for this controller instance.
 * Uses ESTA manufacturer ID 0x7FF0 (prototype/development).
 */
function makeUID() {
  const buf = Buffer.alloc(6)
  buf.writeUInt16BE(0x7FF0, 0)
  for (let i = 2; i < 6; i++) buf[i] = Math.floor(Math.random() * 256)
  return buf
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
  // LLRP PDU structure: Flags+Length(2) + Vector(4) + Dest CID Header(16) + Data(N)
  // Total header overhead: 2 + 4 + 16 = 22 bytes minimum
  if (rootVec === VECTOR_ROOT_LLRP && childBuf.length >= 22) {
    const llrpLen = ((childBuf[0] & 0x0F) << 8) | childBuf[1]
    const llrpVec = childBuf.readUInt32BE(2)
    // LLRP header = Destination CID (16 bytes) at offset 6..22
    const llrpDestCID = childBuf.slice(6, 22)
    // LLRP data starts AFTER the 16-byte Dest CID header (offset 22)
    const llrpData = childBuf.slice(22, llrpLen)

    result.llrpVector = llrpVec
    result.llrpDestCID = llrpDestCID.toString('hex')

    if (llrpVec === VECTOR_LLRP_PROBE_REPLY) {
      result.type = 'llrp_probe_reply'
      // Probe Reply: UID(6) + HW Address(6) + Component Type(1) = 13 bytes
      // Data is directly in LLRP PDU (no inner PDU wrapper)
      if (llrpData.length >= 6) {
        result.uid  = llrpData.slice(0, 6).toString('hex').toUpperCase()
        result.uidStr = `${result.uid.slice(0,4)}:${result.uid.slice(4)}`
        if (llrpData.length >= 12) {
          result.hwAddr = llrpData.slice(6, 12).toString('hex').match(/../g).join(':')
        }
        if (llrpData.length >= 13) {
          result.componentType = llrpData[12]
        }
      }
    } else if (llrpVec === VECTOR_LLRP_PROBE_REQUEST) {
      result.type = 'llrp_probe_request'
    } else if (llrpVec === VECTOR_LLRP_RDM_CMD) {
      result.type = 'llrp_rdm_cmd'
      result.destCID = llrpDestCID.toString('hex')
      // LLRP RDM CMD data = raw RDM packet (directly in LLRP data)
      result.rdmData = llrpData
    }
  }

  // Parse Broker layer
  if (rootVec === VECTOR_ROOT_BROKER && childBuf.length >= 6) {
    const brokerLen = ((childBuf[0] & 0x0F) << 8) | childBuf[1]
    const brokerVec = childBuf.readUInt32BE(2)
    const brokerData = childBuf.slice(6, brokerLen)

    if (brokerVec === VECTOR_BROKER_CONNECT_REPLY) {
      result.type = 'broker_connect_reply'
      // Connect Reply data: Connection Code (2 bytes) + E1.33 Version (2 bytes)
      // + Broker UID (6 bytes) + Client UID (6 bytes)
      if (brokerData.length >= 2) {
        result.connectionCode = brokerData.readUInt16BE(0)
        result.connected = (result.connectionCode === BROKER_OK)
      }
      if (brokerData.length >= 4) result.brokerVersion = brokerData.readUInt16BE(2)
      if (brokerData.length >= 10) result.brokerUID = brokerData.slice(4, 10).toString('hex').toUpperCase()
      if (brokerData.length >= 16) result.clientUID = brokerData.slice(10, 16).toString('hex').toUpperCase()
    } else if (brokerVec === VECTOR_BROKER_CONNECTED_CLIENT_LIST ||
               brokerVec === VECTOR_BROKER_CLIENT_ADD) {
      result.type = brokerVec === VECTOR_BROKER_CLIENT_ADD ? 'broker_client_add' : 'broker_client_list'
      result.clients = _parseBrokerClientEntries(brokerData)
    } else if (brokerVec === VECTOR_BROKER_CLIENT_REMOVE) {
      result.type = 'broker_client_remove'
      result.clients = _parseBrokerClientEntries(brokerData)
    }
  }

  // Parse RPT layer
  if (rootVec === VECTOR_ROOT_RPT && childBuf.length >= 6) {
    const rptLen = ((childBuf[0] & 0x0F) << 8) | childBuf[1]
    const rptVec = childBuf.readUInt32BE(2)
    // RPT header: srcUID(6) + srcEndpoint(2) + destUID(6) + destEndpoint(2) + seqNum(4) = 20 bytes
    const rptBody = childBuf.slice(6, rptLen)

    if (rptBody.length >= 20) {
      result.srcUID       = rptBody.slice(0, 6).toString('hex').toUpperCase()
      result.srcEndpoint  = rptBody.readUInt16BE(6)
      result.destUID      = rptBody.slice(8, 14).toString('hex').toUpperCase()
      result.destEndpoint = rptBody.readUInt16BE(14)
      result.seqNum       = rptBody.readUInt32BE(16)

      const rptPayload = rptBody.slice(20)

      if (rptVec === VECTOR_RPT_NOTIFICATION && rptPayload.length >= 6) {
        result.type = 'rpt_notification'
        // Parse nested RDM Command PDU: flags+length(2) + vector(4) + data
        const innerLen = ((rptPayload[0] & 0x0F) << 8) | rptPayload[1]
        result.rdmData = rptPayload.slice(6, innerLen)
      } else if (rptVec === VECTOR_RPT_STATUS) {
        result.type = 'rpt_status'
        if (rptPayload.length >= 6) {
          result.statusCode = rptPayload.readUInt32BE(2)
        }
      } else if (rptVec === VECTOR_RPT_REQUEST) {
        result.type = 'rpt_request'
      }
    }
  }

  return result
  } catch (_) { return null }
}

/** Parse Client Entry PDUs from Broker messages */
function _parseBrokerClientEntries(data) {
  const entries = []
  let off = 0
  while (off + 6 <= data.length) {
    const entryLen = ((data[off] & 0x0F) << 8) | data[off + 1]
    if (entryLen < 6 || off + entryLen > data.length) break
    const entryData = data.slice(off + 6, off + entryLen)  // skip flags+length+vector
    if (entryData.length >= 39) {
      entries.push({
        cid:        entryData.slice(0, 16).toString('hex'),
        uid:        entryData.slice(16, 22).toString('hex').toUpperCase(),
        uidStr:     `${entryData.slice(16, 18).toString('hex').toUpperCase()}:${entryData.slice(18, 22).toString('hex').toUpperCase()}`,
        clientType: entryData[22],  // 1=Controller, 2=Device
        bindingCID: entryData.slice(23, 39).toString('hex'),
      })
    }
    off += entryLen
  }
  return entries
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
    this.uid         = makeUID()
    this.socket      = null   // UDP for LLRP
    this.tcpSockets  = new Map()  // ip → { socket, state, buf, callbacks }
    this._brokers    = new Map()  // ip → broker info
    this._rptSeq     = 1          // RPT sequence number counter
    this._llrpDevices = new Map() // ip → { cid (Buffer), uid, uidStr }
  }

  // ─── LLRP UDP Probe ────────────────────────────────────────────────────────

  /**
   * Open UDP socket on port 5569 and start listening for LLRP responses.
   *
   * E1.33 requires LLRP traffic on port 5569 — both sending and receiving.
   * We bind to an EPHEMERAL port (not 5569) to avoid conflicting with
   * the Pathport's own LLRP listener on port 5569.  LLRP probe replies
   * are sent back to the source IP:port of the probe, so ephemeral works.
   *
   * @param {string} [localIP='0.0.0.0'] - Local interface IP for multicast.
   *   Pass the scan interface IP so multicast probes go out the right NIC.
   * @returns {Promise<void>}
   */
  startUDP(localIP = '0.0.0.0') {
    return new Promise((resolve, reject) => {
      if (this.socket) return resolve()

      this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })

      this.socket.on('message', (msg, rinfo) => {
        try {
          const pkt = parseACNPacket(msg)
          if (!pkt) return

          if (pkt.type === 'llrp_probe_reply') {
            // Cache the device's CID for later LLRP RDM commands
            if (pkt.cid && pkt.uid) {
              this._llrpDevices.set(rinfo.address, {
                cid: Buffer.from(pkt.cid, 'hex'),
                uid: pkt.uid,
                uidStr: pkt.uidStr,
              })
            }
            this.emit('llrpReply', { ip: rinfo.address, ...pkt })
          } else if (pkt.type === 'llrp_rdm_cmd') {
            this.emit('llrpRdmResponse', { ip: rinfo.address, ...pkt })
          }
        } catch (_) {}
      })

      this.socket.on('error', (err) => {
        // Only emit if someone is listening — otherwise swallow to prevent crash
        if (this.listenerCount('error') > 0) this.emit('error', err)
      })

      // Bind to EPHEMERAL port (port 0) — NOT port 5569.
      // Binding to 5569 caused Pathport nodes to go offline, likely because
      // our socket on that port conflicted with their LLRP listener.
      // LLRP replies are unicast back to our source port, so ephemeral works.
      this.socket.bind({ port: 0, address: '0.0.0.0' }, () => {
        try { this.socket.setBroadcast(true) } catch (_) {}
        // E1.33 requires multicastTTL(20) for LLRP traffic
        try { this.socket.setMulticastTTL(20) } catch (_) {}
        // Set the outgoing multicast interface so probes go out the right NIC
        if (localIP && localIP !== '0.0.0.0') {
          try { this.socket.setMulticastInterface(localIP) } catch (_) {}
        }
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
   * Send LLRP probes on multicast, broadcast, and unicast to discover
   * RDMnet devices and populate the _llrpDevices cache.
   *
   * E1.33 spec requires probes go to multicast 239.255.250.133:5569.
   * We also send to subnet broadcasts (catches non-compliant devices)
   * and direct unicast to any specific IPs provided.
   *
   * NOTE: Does NOT close the UDP socket afterwards — caller is responsible
   * for cleanup (scanner.stop() → rdmnet.destroy()).
   *
   * @param {number}   [listenMs=3000]  - How long to listen for replies
   * @param {string[]} [extraIPs=[]]    - Additional IPs to probe via unicast
   * @param {string}   [localIP='0.0.0.0'] - Local interface IP for multicast
   * @returns {Promise<Array>} - Array of LLRP replies
   */
  async broadcastProbe(listenMs = 3000, extraIPs = [], localIP = '0.0.0.0') {
    const replies = []
    const seen    = new Set()

    await this.startUDP(localIP)

    const handler = (reply) => {
      if (!seen.has(reply.ip)) {
        seen.add(reply.ip)
        replies.push(reply)
      }
    }
    this.on('llrpReply', handler)

    // === GENTLE PROBE STRATEGY ===
    // Previous versions sent 14+ packets in rapid succession which caused
    // Pathport nodes to crash/go offline.  Now we send minimal probes
    // with 150ms spacing to be gentle on the network.

    // 1. Single LLRP multicast probe (the spec-compliant method)
    this.sendLLRPProbe(LLRP_MULTICAST)
    await _delay(150)

    // 2. Direct unicast to known manual node IPs only (no broadcast flood)
    for (const ip of extraIPs) {
      this.sendLLRPProbe(ip)
      await _delay(150)
    }

    // Wait for replies
    await _delay(listenMs)

    this.off('llrpReply', handler)
    // Do NOT stopUDP() here — the socket is needed for per-node LLRP RDM
    // scanning that follows.  Scanner.stop() → rdmnet.destroy() handles cleanup.

    return replies
  }

  /**
   * Send unicast LLRP probes to a specific IP and wait for a reply.
   * Used as a per-node fallback when the initial broadcast probe didn't
   * reach a particular device.
   *
   * @param {string} ip           - Target IP
   * @param {number} [listenMs=1500]
   * @returns {Promise<object|null>} - LLRP reply or null
   */
  async probeIPDirect(ip, listenMs = 1500) {
    // Check cache first
    if (this._llrpDevices.has(ip)) {
      return { ip, cached: true, ...this._formatLLRPDevice(ip) }
    }

    await this.startUDP()

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.off('llrpReply', handler)
        resolve(null)
      }, listenMs)

      const handler = (reply) => {
        if (reply.ip === ip) {
          clearTimeout(timer)
          this.off('llrpReply', handler)
          resolve(reply)
        }
      }
      this.on('llrpReply', handler)

      // Single gentle probe — previous 3x rapid-fire caused node instability
      this.sendLLRPProbe(ip)
    })
  }

  _formatLLRPDevice(ip) {
    const dev = this._llrpDevices.get(ip)
    if (!dev) return {}
    return { cid: dev.cid.toString('hex'), uid: dev.uid, uidStr: dev.uidStr }
  }

  // ─── LLRP RDM Commands ──────────────────────────────────────────────────────

  /**
   * Get cached LLRP device info for an IP (from earlier probe replies).
   * @param {string} ip
   * @returns {{ cid: Buffer, uid: string, uidStr: string } | null}
   */
  getLLRPDevice(ip) {
    return this._llrpDevices.get(ip) || null
  }

  /**
   * Send an RDM command to a device via LLRP (UDP unicast, bypasses broker).
   * @param {string} ip         - Device IP
   * @param {Buffer} destCID    - Device CID (16 bytes)
   * @param {Buffer} rdmPacket  - Complete RDM packet (starting with 0xCC)
   * @param {number} timeout    - Response timeout in ms
   * @returns {Promise<Buffer|null>} - RDM response data, or null on timeout
   */
  sendLLRPRdm(ip, destCID, rdmPacket, timeout = 600) {
    return new Promise(async (resolve) => {
      const timer = setTimeout(() => {
        this.off('llrpRdmResponse', handler)
        resolve(null)
      }, timeout)

      try { await this.startUDP() } catch (_) {
        clearTimeout(timer)
        return resolve(null)
      }

      const handler = (reply) => {
        if (reply.ip === ip && reply.rdmData) {
          clearTimeout(timer)
          this.off('llrpRdmResponse', handler)
          resolve(reply.rdmData)
        }
      }
      this.on('llrpRdmResponse', handler)

      const pkt = buildLLRPRdmCommand(this.cid, destCID, rdmPacket)
      this.socket.send(pkt, 0, pkt.length, RDMNET_PORT, ip, () => {})
    })
  }

  // ─── RPT Controller (Broker Connection) ───────────────────────────────────

  /**
   * Connect to an RDMnet broker as an RPT Controller.
   * Sends a Broker Connect message and waits for Connect Reply.
   *
   * @param {string} ip           - Broker IP
   * @param {number} [port=5569]  - Broker port
   * @param {number} [timeoutMs=5000]
   * @returns {Promise<{ connected: boolean, clients: Array, error?: string }>}
   */
  connectBroker(ip, port = RDMNET_PORT, timeoutMs = 5000) {
    return new Promise((resolve) => {
      if (this.tcpSockets.has(ip)) {
        const existing = this.tcpSockets.get(ip)
        if (existing.state === CONN_CONNECTED) return resolve({ connected: true, clients: existing.clients || [] })
        // Clean up stale connection
        try { existing.socket.destroy() } catch (_) {}
        this.tcpSockets.delete(ip)
      }

      const sock = new net.Socket()
      let rxBuf  = Buffer.alloc(0)
      let done   = false
      const clients = []
      const entry = { socket: sock, state: CONN_CONNECTING, buf: rxBuf, clients, callbacks: new Map() }
      this.tcpSockets.set(ip, entry)

      const finish = (result) => {
        if (done) return
        done = true
        clearTimeout(timer)
        if (!result.connected) {
          try { sock.destroy() } catch (_) {}
          this.tcpSockets.delete(ip)
        }
        resolve(result)
      }

      const timer = setTimeout(() => finish({ connected: false, clients: [], error: 'timeout' }), timeoutMs)

      sock.connect(port, ip, () => {
        // Send Broker Connect message
        const connectMsg = buildBrokerConnect(this.cid, this.uid)
        sock.write(connectMsg)
      })

      sock.on('data', (chunk) => {
        rxBuf = Buffer.concat([rxBuf, chunk])
        entry.buf = rxBuf

        // Parse all complete packets from the TCP stream
        const { packets, remainder } = parseTCPStream(rxBuf)
        rxBuf = remainder
        entry.buf = rxBuf

        for (const pkt of packets) {
          if (pkt.type === 'broker_connect_reply') {
            if (pkt.connected) {
              entry.state = CONN_CONNECTED
              this._brokers.set(ip, { uid: pkt.brokerUID, version: pkt.brokerVersion })
              this.emit('brokerConnected', { ip, brokerUID: pkt.brokerUID })
              // Don't finish yet — wait briefly for client list
              setTimeout(() => {
                if (!done) finish({ connected: true, clients: entry.clients })
              }, 500)
            } else {
              finish({ connected: false, clients: [], error: `broker rejected: code ${pkt.connectionCode}` })
            }
          } else if (pkt.type === 'broker_client_list' || pkt.type === 'broker_client_add') {
            for (const c of (pkt.clients || [])) {
              if (!clients.find(e => e.uid === c.uid)) clients.push(c)
            }
            entry.clients = clients
            this.emit('brokerClientUpdate', { ip, clients })
          } else if (pkt.type === 'broker_client_remove') {
            for (const c of (pkt.clients || [])) {
              const idx = clients.findIndex(e => e.uid === c.uid)
              if (idx >= 0) clients.splice(idx, 1)
            }
            entry.clients = clients
          } else if (pkt.type === 'rpt_notification' || pkt.type === 'rpt_status') {
            // Route RPT responses to pending callbacks
            const seqKey = pkt.seqNum
            const cb = entry.callbacks.get(seqKey)
            if (cb) {
              entry.callbacks.delete(seqKey)
              cb(pkt)
            }
          }
        }
      })

      sock.on('error', () => finish({ connected: false, clients: [], error: 'connection refused' }))
      sock.on('close', () => {
        entry.state = CONN_DISCONNECTED
        if (!done) finish({ connected: false, clients: [], error: 'connection closed' })
      })
    })
  }

  /**
   * Disconnect from a broker.
   */
  disconnectBroker(ip) {
    const entry = this.tcpSockets.get(ip)
    if (entry) {
      try { entry.socket.destroy() } catch (_) {}
      this.tcpSockets.delete(ip)
    }
    this._brokers.delete(ip)
  }

  /**
   * Check if we have an active broker connection.
   * @param {string} [ip] - Specific broker IP, or omit to check any
   * @returns {{ ip: string, entry: object } | null}
   */
  getConnectedBroker(ip) {
    if (ip) {
      const entry = this.tcpSockets.get(ip)
      return entry && entry.state === CONN_CONNECTED ? { ip, entry } : null
    }
    // Find any connected broker
    for (const [brokerIP, entry] of this.tcpSockets) {
      if (entry.state === CONN_CONNECTED) return { ip: brokerIP, entry }
    }
    return null
  }

  /**
   * Get the list of RPT Device clients reported by a connected broker.
   * @param {string} ip - Broker IP
   * @returns {Array} - Client entries with { cid, uid, uidStr, clientType }
   */
  getBrokerClients(ip) {
    const entry = this.tcpSockets.get(ip)
    return entry ? (entry.clients || []).filter(c => c.clientType === 2) : []  // type 2 = Device
  }

  /**
   * Send an RDM command through a broker via RPT.
   *
   * @param {string} brokerIP      - Broker IP we're connected to
   * @param {Buffer} destUID       - Target device UID (6 bytes)
   * @param {number} destEndpoint  - Target endpoint (0 = device, 1+ = port)
   * @param {Buffer} rdmPacket     - Complete RDM packet
   * @param {number} timeout       - Response timeout in ms
   * @returns {Promise<Buffer|null>} - RDM response data, or null on timeout
   */
  sendRPTRdm(brokerIP, destUID, destEndpoint, rdmPacket, timeout = 800) {
    return new Promise((resolve) => {
      const entry = this.tcpSockets.get(brokerIP)
      if (!entry || entry.state !== CONN_CONNECTED) return resolve(null)

      const seq = this._rptSeq++
      const timer = setTimeout(() => {
        entry.callbacks.delete(seq)
        resolve(null)
      }, timeout)

      entry.callbacks.set(seq, (pkt) => {
        clearTimeout(timer)
        resolve(pkt.rdmData || null)
      })

      const pktBuf = buildRPTRequest(this.cid, this.uid, destUID, destEndpoint, seq, rdmPacket)
      try {
        entry.socket.write(pktBuf)
      } catch (_) {
        clearTimeout(timer)
        entry.callbacks.delete(seq)
        resolve(null)
      }
    })
  }

  destroy() {
    this.stopUDP()
    for (const [ip, entry] of this.tcpSockets) {
      try { entry.socket.destroy() } catch (_) {}
    }
    this.tcpSockets.clear()
    this._brokers.clear()
    this._llrpDevices.clear()
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
