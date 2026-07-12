/**
 * rdmnet-broker.js
 * Embedded E1.33 RDMnet Broker for RDM Explorer.
 *
 * Runs a TCP server on port 5569 and advertises itself via mDNS as
 * _rdmnet._tcp.local, so that RDMnet-capable gateway devices (such as
 * Pathway Pathports configured with "RDM Transport: E1.33 RDMnet (Unsecured)")
 * can automatically discover and connect to this app.
 *
 * Once a gateway (RPT Device) is connected, the scanner can send RDM commands
 * through the broker using sendRdm(), and RDM responses come back as Promises.
 *
 * Architecture:
 *   Scanner (in-process controller)
 *       ↓ broker.sendRdm(gatewayCID, destUID, endpoint, rdmPacket)
 *   RDMnetBroker (TCP server, this file)
 *       ↓ RPT Request over TCP
 *   Pathport RPT Gateway (physical device on network)
 *       ↓ physical DMX/RDM to fixtures
 *   RDM Fixture
 *
 * E1.33 References:
 *   §5   LLRP
 *   §6   Broker
 *   §7   RPT (RDM Packet Transport)
 *   Table A-3: Root Layer vectors
 *   Table A-8: Broker PDU vectors
 *   Table A-11: RPT PDU vectors
 */

'use strict'

const net          = require('net')
const dgram        = require('dgram')
const { spawn, execFile } = require('child_process')
const EventEmitter = require('events')
const os           = require('os')

// ─── Constants ────────────────────────────────────────────────────────────────

// Module-level response dedup — shared across ALL RDMnetBroker instances.
// During tests, multiple broker instances exist simultaneously (unit-test brokers +
// _sharedBroker).  Per-instance dedup is not sufficient; this module-level Map
// prevents any two instances from both responding to the same mDNS querier within
// a 500ms window, regardless of how many sockets/instances receive the same packet.
const _globalMDNSResponseDedup = new Map()

const RDMNET_PORT    = 5569
const MDNS_ADDR      = '224.0.0.251'
const MDNS_PORT      = 5353
const KEEPALIVE_MS   = 15000   // Send BROKER_NULL every 15 s
const MDNS_TTL       = 4500    // mDNS record TTL (seconds)
const SERVICE_NAME   = 'RDM-Explorer'

// Root Layer PDU vectors (E1.33 Table A-3)
const VECTOR_ROOT_BROKER  = 0x00000009
const VECTOR_ROOT_RPT     = 0x00000005

// Broker PDU vectors (E1.33 Table A-8 / ETC RDMnet rdmnet/defs.h — verified Session 45).
// The values used before Session 45 were WRONG: NULL was 0x0005 (actually REDIRECT_V6!)
// and DISCONNECT was 0x0004 (actually REDIRECT_V4).  Every keepalive we sent told the
// Pathport to redirect to another broker.
const VECTOR_BROKER_CONNECT                 = 0x0001
const VECTOR_BROKER_CONNECT_REPLY           = 0x0002
const VECTOR_BROKER_CLIENT_ENTRY_UPDATE     = 0x0003
const VECTOR_BROKER_REDIRECT_V4             = 0x0004
const VECTOR_BROKER_REDIRECT_V6             = 0x0005
const VECTOR_BROKER_FETCH_CLIENT_LIST       = 0x0006
const VECTOR_BROKER_CONNECTED_CLIENT_LIST   = 0x0007
const VECTOR_BROKER_CLIENT_ADD              = 0x0008
const VECTOR_BROKER_CLIENT_REMOVE           = 0x0009
const VECTOR_BROKER_DISCONNECT              = 0x000E
const VECTOR_BROKER_NULL                    = 0x000F

// Client Entry PDU vector = client protocol code (E1.33 §6.2.3 / ETC defs.h).
// The Pathport's own BROKER_CONNECT carries 0x00000005 here — earlier sessions
// logged it as an "unusual vector value"; it is simply CLIENT_PROTOCOL_RPT.
const CLIENT_PROTOCOL_RPT                   = 0x00000005

// RPT PDU vectors (E1.33 Table A-11)
const VECTOR_RPT_REQUEST      = 0x00000001
const VECTOR_RPT_STATUS       = 0x00000002
const VECTOR_RPT_NOTIFICATION = 0x00000003

// Request / Notification PDU vectors (E1.33 §7.5.2 / §7.5.3) — 4 bytes
const VECTOR_REQUEST_RDM_CMD      = 0x00000001
const VECTOR_NOTIFICATION_RDM_CMD = 0x00000001

// RDM Command PDU vector (E1.33 §7.5.5) — a SINGLE byte, always 0xCC (the RDM
// start code).  The PDU data is the RDM message WITHOUT its start code.
const VECTOR_RDM_CMD_RDM_DATA     = 0xCC

// Broker Connect Reply codes
const BROKER_OK             = 0x0000
const BROKER_CAPACITY_FULL  = 0x0003
const BROKER_WRONG_SCOPE    = 0x0004

// E1.33 protocol version
const E133_VERSION = 0x0001

// RPT client types in Client Entry PDU (E1.33 Table 6-15).
// DEVICE is 0x00, NOT 0x02 — the pre-Session-45 value 0x02 is undefined in the spec.
// Real Pathports declare type 0x00; the old code only worked because 0 is falsy and
// fell through a `|| CLIENT_TYPE_DEVICE` fallback.
const CLIENT_TYPE_DEVICE     = 0x00  // RPT Device (gateway / fixture)
const CLIENT_TYPE_CONTROLLER = 0x01

// ── Broker-layer vector size for E1.33-framed clients ──────────────────────────
// Per ANSI E1.33 (verified against ETC RDMnet broker_prot.c PACK_BROKER_HEADER,
// Session 45): the Broker PDU vector is ALWAYS 2 bytes, and the FL field is always
// the 3-byte/20-bit form.  What earlier sessions called the "Pathport variant" is
// simply the standard — the Pathport was spec-compliant all along.
// The Attempt 24 hypothesis (4-byte vectors) contradicted the spec and was never
// validated on hardware.  The auto-fallback in _getEffectiveVecSize() remains as a
// safety net and will flip to 4 if a device ever rejects the 2-byte form.
const PATHPORT_OUTGOING_VEC_SIZE = 2

// ACN Packet Identifier (E1.17) — first 12 bytes after preamble
const ACN_PID = Buffer.from('4153432d45312e313700000000000000', 'hex').slice(0, 12)

// ─── PDU Helpers (self-contained copies; intentionally not importing rdmnet.js
//     to keep broker.js usable standalone) ──────────────────────────────────────

function flagsAndLength(bodyLen) {
  // 2-byte / 12-bit flags+length encoding (E1.17 standard, top bit clear)
  const total = bodyLen + 2
  return [0x70 | ((total >> 8) & 0x0F), total & 0xFF]
}

function flagsAndLength3(bodyLen) {
  // 3-byte / 20-bit flags+length encoding (top bit set).
  // Pathport firmware uses and expects this format throughout all PDU layers.
  const total = bodyLen + 3
  return [0xF0 | ((total >> 16) & 0x0F), (total >> 8) & 0xFF, total & 0xFF]
}

function buildPDU(vector, header, data, vecSize = 4, use3ByteLen = false) {
  // vecSize=4 for root layer (always); vecSize=2 for broker/RPT layers when talking to Pathport firmware.
  // use3ByteLen=true produces 3-byte flags+length header (required for Pathport firmware).
  const body = Buffer.alloc(vecSize + header.length + data.length)
  if (vecSize === 2) body.writeUInt16BE(vector, 0)
  else body.writeUInt32BE(vector, 0)
  header.copy(body, vecSize)
  data.copy(body, vecSize + header.length)
  if (use3ByteLen) {
    const [b0, b1, b2] = flagsAndLength3(body.length)
    const out = Buffer.alloc(3 + body.length)
    out[0] = b0; out[1] = b1; out[2] = b2
    body.copy(out, 3)
    return out
  } else {
    const [hi, lo] = flagsAndLength(body.length)
    const out = Buffer.alloc(2 + body.length)
    out[0] = hi; out[1] = lo
    body.copy(out, 2)
    return out
  }
}

function wrap(pdu) {
  // Prepend the standard 16-byte ACN preamble (E1.17 §2.4)
  // Layout: preamble_size(2) + postamble_size(2) + ACN_PID(12)
  const pre = Buffer.alloc(16)
  pre.writeUInt16BE(0x0010, 0)
  pre.writeUInt16BE(0x0000, 2)
  ACN_PID.copy(pre, 4)
  return Buffer.concat([pre, pdu])
}

function wrapPathport(pdu) {
  // Pathport variant 16-byte preamble: ACN_PID(12) + remaining_length(4)
  // Pathport firmware sends and expects this format (ACN_PID at byte 0, not byte 4).
  const pre = Buffer.alloc(16)
  ACN_PID.copy(pre, 0)
  pre.writeUInt32BE(pdu.length, 12)
  return Buffer.concat([pre, pdu])
}

function makeCID() {
  const b = Buffer.alloc(16)
  for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256)
  b[6] = (b[6] & 0x0f) | 0x40
  b[8] = (b[8] & 0x3f) | 0x80
  return b
}

function makeUID() {
  const b = Buffer.alloc(6)
  b.writeUInt16BE(0x7FF0, 0)
  for (let i = 2; i < 6; i++) b[i] = Math.floor(Math.random() * 256)
  return b
}

function uidStr(uid) {
  if (!uid || uid.length < 6) return '0000:00000000'
  return `${uid.slice(0,2).toString('hex').toUpperCase()}:${uid.slice(2,6).toString('hex').toUpperCase()}`
}

/**
 * Load the persisted broker identity (CID + UID), creating and saving a new one
 * on first run. Stored in the per-user application data directory so packaged
 * and dev runs on the same machine share one identity.
 */
function loadOrCreateBrokerIdentity() {
  const fs = require('fs')
  const path = require('path')
  const dir = process.platform === 'darwin'
    ? path.join(os.homedir(), 'Library', 'Application Support', 'rdm-explorer')
    : path.join(os.homedir(), '.rdm-explorer')
  const file = path.join(dir, 'broker-identity.json')
  try {
    const j = JSON.parse(fs.readFileSync(file, 'utf8'))
    const cid = Buffer.from(j.cid, 'hex')
    const uid = Buffer.from(j.uid, 'hex')
    if (cid.length === 16 && uid.length === 6) return { cid, uid }
  } catch (_) { /* first run or unreadable — create below */ }
  const ident = { cid: makeCID(), uid: makeUID() }
  try {
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(file, JSON.stringify({ cid: ident.cid.toString('hex'), uid: ident.uid.toString('hex') }))
  } catch (_) { /* persistence is best-effort; a volatile identity still works */ }
  return ident
}

// ─── Packet Builders ──────────────────────────────────────────────────────────

/**
 * Build a BROKER_CONNECT_REPLY packet.
 * Sent over TCP to a client (RPT Device or Controller) after they send BROKER_CONNECT.
 *
 * Data layout (E1.33 §6.3.3):
 *   Connection Code  2 bytes  BE   (0x0000 = OK)
 *   E1.33 Version    2 bytes  BE
 *   Broker UID       6 bytes
 *   Client UID       6 bytes
 */
function buildConnectReply(brokerCID, brokerUID, clientUID, code = BROKER_OK, pathportFormat = false, vecSizeOverride = null) {
  const data = Buffer.alloc(16)
  data.writeUInt16BE(code, 0)
  data.writeUInt16BE(E133_VERSION, 2)
  brokerUID.copy(data, 4)
  clientUID.copy(data, 10)
  // Attempt 24: Pathport firmware SENDS 2-byte broker vectors but appears to READ
  // 4-byte vectors in incoming broker PDUs (asymmetric encoding).  See PATHPORT_OUTGOING_VEC_SIZE
  // for the Attempt 26 fallback if 4-byte turns out to be wrong.
  // vecSizeOverride: explicitly set by auto-fallback logic; null = use PATHPORT_OUTGOING_VEC_SIZE
  const vs = vecSizeOverride !== null ? vecSizeOverride : (pathportFormat ? PATHPORT_OUTGOING_VEC_SIZE : 4)
  const brokerPDU = buildPDU(VECTOR_BROKER_CONNECT_REPLY, Buffer.alloc(0), data, vs, pathportFormat)
  const rootPDU = buildPDU(VECTOR_ROOT_BROKER, brokerCID, brokerPDU, 4, pathportFormat)
  return pathportFormat ? wrapPathport(rootPDU) : wrap(rootPDU)
}

/**
 * Build a BROKER_NULL keepalive packet.
 * Sent periodically to keep TCP connections alive.
 */
function buildBrokerNull(brokerCID, pathportFormat = false, vecSizeOverride = null) {
  const vs = vecSizeOverride !== null ? vecSizeOverride : (pathportFormat ? PATHPORT_OUTGOING_VEC_SIZE : 4)
  const brokerPDU = buildPDU(VECTOR_BROKER_NULL, Buffer.alloc(0), Buffer.alloc(0), vs, pathportFormat)
  const rootPDU = buildPDU(VECTOR_ROOT_BROKER, brokerCID, brokerPDU, 4, pathportFormat)
  return pathportFormat ? wrapPathport(rootPDU) : wrap(rootPDU)
}

/**
 * Build a single Client Entry PDU for an RPT client.
 * Used inside BROKER_CONNECTED_CLIENT_LIST and BROKER_CLIENT_ADD.
 *
 * RPT Client Entry data layout (E1.33 Table 6-14):
 *   CID          16 bytes
 *   UID           6 bytes
 *   Client Type   1 byte   (0x01=Controller, 0x02=Device/Gateway)
 *   Binding CID  16 bytes  (zeros unless type=Device with binding)
 * Total: 39 bytes
 */
function buildClientEntryPDU(cidBuf, uidBuf, clientType, pathportFormat = false) {
  const data = Buffer.alloc(39)
  cidBuf.copy(data, 0)       // CID: bytes 0–15
  uidBuf.copy(data, 16)      // UID: bytes 16–21
  data[22] = clientType      // Client type: byte 22 (0x00=Device, 0x01=Controller)
  // bytes 23–38: Binding CID = zeros (not used here)
  // Vector = client protocol code, always 4 bytes (E1.33 §6.2.3).  Matches the
  // 46-byte entry with vector 0x00000005 real Pathports send in BROKER_CONNECT.
  return buildPDU(CLIENT_PROTOCOL_RPT, Buffer.alloc(0), data, 4, pathportFormat)
}

/**
 * Build a BROKER_CONNECTED_CLIENT_LIST packet.
 * Sent immediately after BROKER_CONNECT_REPLY (E1.33 §6.3.4.c).
 * Contains one Client Entry PDU per currently connected RPT client,
 * NOT including the newly connected client.
 * An empty list (no other clients) is perfectly valid.
 *
 * @param {Buffer}   brokerCID     - This broker's CID
 * @param {Buffer[]} clientPDUs    - Array of Client Entry PDUs (may be empty)
 * @param {boolean}  pathportFormat - Use 2-byte broker vectors for Pathport firmware
 */
function buildConnectedClientList(brokerCID, clientPDUs, pathportFormat = false, vecSizeOverride = null) {
  const data = clientPDUs.length > 0 ? Buffer.concat(clientPDUs) : Buffer.alloc(0)
  const vs = vecSizeOverride !== null ? vecSizeOverride : (pathportFormat ? PATHPORT_OUTGOING_VEC_SIZE : 4)
  const brokerPDU = buildPDU(VECTOR_BROKER_CONNECTED_CLIENT_LIST, Buffer.alloc(0), data, vs, pathportFormat)
  const rootPDU = buildPDU(VECTOR_ROOT_BROKER, brokerCID, brokerPDU, 4, pathportFormat)
  return pathportFormat ? wrapPathport(rootPDU) : wrap(rootPDU)
}

/**
 * Build a BROKER_CLIENT_ADD packet.
 * Sent to ALL existing connected clients when a new RPT client joins (E1.33 §6.3.4.d).
 * Contains one Client Entry PDU for the newly connected client.
 *
 * @param {Buffer} brokerCID   - This broker's CID
 * @param {Buffer} newClientPDU - Client Entry PDU for the new client
 * @param {boolean} pathportFormat - Use 2-byte broker vectors for Pathport firmware
 */
function buildClientAdd(brokerCID, newClientPDU, pathportFormat = false, vecSizeOverride = null) {
  const vs = vecSizeOverride !== null ? vecSizeOverride : (pathportFormat ? PATHPORT_OUTGOING_VEC_SIZE : 4)
  const brokerPDU = buildPDU(VECTOR_BROKER_CLIENT_ADD, Buffer.alloc(0), newClientPDU, vs, pathportFormat)
  const rootPDU = buildPDU(VECTOR_ROOT_BROKER, brokerCID, brokerPDU, 4, pathportFormat)
  return pathportFormat ? wrapPathport(rootPDU) : wrap(rootPDU)
}

/**
 * Build an RPT Request packet wrapping an RDM command.
 * Sent over TCP to a connected RPT Gateway (Pathport) to deliver an RDM command.
 *
 * RPT Header layout (E1.33 §7.5.1):
 *   Source UID       6 bytes  (controller UID)
 *   Source Endpoint  2 bytes  BE  (0 = controller endpoint)
 *   Dest UID         6 bytes
 *   Dest Endpoint    2 bytes  BE  (0 = gateway itself; 1+ = physical port)
 *   Sequence Number  4 bytes  BE
 */
function buildRPTRequest(brokerCID, ctrlUID, destUID, destEndpoint, seqNum, rdmPacket, pathportFormat = false, vecSizeOverride = null) {
  if (pathportFormat) {
    // Spec-compliant E1.33 framing (verified against ETC RDMnet rpt_prot.c):
    //   RPT PDU: 3-byte FL + 4-byte vector + 21-byte header (incl. trailing reserved byte)
    //     Request PDU: 3-byte FL + 4-byte vector (0x00000001)
    //       RDM Command PDU: 3-byte FL + 1-byte vector 0xCC + RDM message minus start code
    const hdr = Buffer.alloc(21)
    ctrlUID.copy(hdr, 0)
    hdr.writeUInt16BE(0, 6)             // src endpoint: controller (NULL_ENDPOINT)
    destUID.copy(hdr, 8)
    hdr.writeUInt16BE(destEndpoint, 14)
    hdr.writeUInt32BE(seqNum >>> 0, 16)
    hdr[20] = 0                          // reserved

    const rdmBody = rdmPacket[0] === 0xCC ? rdmPacket.slice(1) : rdmPacket
    const cmdBody = Buffer.alloc(1 + rdmBody.length)
    cmdBody[0] = VECTOR_RDM_CMD_RDM_DATA
    rdmBody.copy(cmdBody, 1)
    const [c0, c1, c2] = flagsAndLength3(cmdBody.length)
    const rdmCmdPDU = Buffer.concat([Buffer.from([c0, c1, c2]), cmdBody])

    const requestPDU = buildPDU(VECTOR_REQUEST_RDM_CMD, Buffer.alloc(0), rdmCmdPDU, 4, true)
    const rptPDU     = buildPDU(VECTOR_RPT_REQUEST, hdr, requestPDU, 4, true)
    const rootPDU    = buildPDU(VECTOR_ROOT_RPT, brokerCID, rptPDU, 4, true)
    return wrapPathport(rootPDU)
  }

  // Legacy framing kept for interop with rdmnet.js (this app's own controller client):
  // 20-byte header, no Request PDU layer, RDM command PDU with 4-byte vector.
  const hdr = Buffer.alloc(20)
  ctrlUID.copy(hdr, 0)
  hdr.writeUInt16BE(0, 6)           // src endpoint: controller
  destUID.copy(hdr, 8)
  hdr.writeUInt16BE(destEndpoint, 14)
  hdr.writeUInt32BE(seqNum >>> 0, 16)
  const vs = vecSizeOverride !== null ? vecSizeOverride : 4
  const rdmCmdPDU = buildPDU(VECTOR_REQUEST_RDM_CMD, Buffer.alloc(0), rdmPacket, vs, false)
  const rptPDU    = buildPDU(VECTOR_RPT_REQUEST, hdr, rdmCmdPDU, vs, false)
  const rootPDU   = buildPDU(VECTOR_ROOT_RPT, brokerCID, rptPDU, 4, false)
  return wrap(rootPDU)
}

// ─── TCP Stream Parser ────────────────────────────────────────────────────────

/**
 * Parse an E1.17 flags-and-length field.
 *
 * E1.17 §2.3: the length field is either 2 bytes (12-bit, top bit clear) or
 * 3 bytes (20-bit, top bit set).  Standard E1.33 devices use 2-byte encoding;
 * Pathway Pathport devices use 3-byte (20-bit) encoding throughout all layers.
 *
 * Returns { length, headerSize } where:
 *   length     = total PDU octets including the flags+length field itself
 *   headerSize = 2 or 3 (bytes consumed by the flags+length field)
 */
function parseFlagsLen(buf, offset) {
  const b0 = buf[offset]
  if (b0 & 0x80) {
    // 3-byte / 20-bit (top bit set)
    const length = ((b0 & 0x0F) << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
    return { length, headerSize: 3 }
  } else {
    // 2-byte / 12-bit (top bit clear)
    const length = ((b0 & 0x0F) << 8) | buf[offset + 1]
    return { length, headerSize: 2 }
  }
}

/**
 * Parse a TCP byte stream into individual ACN/RDMnet packets.
 * Returns { packets: [], remainder: Buffer }.
 *
 * Each returned packet object has at minimum:
 *   rootVector  {number}
 *   cid         {string}  hex (sender CID from root layer)
 *   type        {string}  'broker_connect' | 'broker_null' | 'broker_disconnect'
 *                         | 'rpt_notification' | 'rpt_status' | 'rpt_request'
 */
function parseTCPStream(buf) {
  const packets = []
  let offset = 0

  while (offset < buf.length) {
    if (offset + 16 > buf.length) break

    // Locate ACN PID.
    // Standard E1.17:   preamble_size(2) + postamble_size(2) + ACN_PID(12) → PID at offset+4
    // Pathport variant: ACN_PID(12) + extra_preamble_bytes(4)              → PID at offset+0
    // Both variants have a 16-byte preamble so the root PDU always starts at offset+16.
    const pidAtStd  = buf.slice(offset + 4, offset + 16).equals(ACN_PID)
    const pidAtZero = buf.slice(offset,     offset + 12).equals(ACN_PID)
    if (!pidAtStd && !pidAtZero) { offset++; continue }

    // Need at least preamble(16) + up to 3 bytes of flags+len
    if (offset + 19 > buf.length) break

    // Root PDU flags+length is always at preamble-offset+16.
    const { length: rootLen } = parseFlagsLen(buf, offset + 16)
    const total = 16 + rootLen
    if (total < 22 || offset + total > buf.length) { offset++; continue }

    const pkt = _parseACNFrame(buf.slice(offset, offset + total))
    if (pkt) packets.push(pkt)
    offset += total
  }

  return { packets, remainder: buf.slice(offset) }
}

function _parseACNFrame(buf) {
  try {
    // Root PDU starts at byte 16 (after 16-byte preamble, regardless of preamble variant).
    // parseFlagsLen handles both 2-byte (standard) and 3-byte (Pathport) encoding.
    const { length: rootLen, headerSize: rootHdr } = parseFlagsLen(buf, 16)
    const rootDataStart = 16 + rootHdr           // 18 for standard, 19 for Pathport
    const rootVec  = buf.readUInt32BE(rootDataStart)
    const rootCID  = buf.slice(rootDataStart + 4, rootDataStart + 20)
    const child    = buf.slice(rootDataStart + 20, 16 + rootLen)

    const result = {
      rootVector: rootVec,
      cid: rootCID.toString('hex'),
      cidBuf: rootCID,
    }

    // ── Broker layer ────────────────────────────────────────────────────────
    if (rootVec === VECTOR_ROOT_BROKER && child.length >= 4) {
      const { length: brkLen, headerSize: brkHdr } = parseFlagsLen(child, 0)
      // Pathport uses 3-byte flags+len (brkHdr=3) → 2-byte vectors; standard uses 2-byte (brkHdr=2) → 4-byte vectors
      const brkVecSize = brkHdr === 3 ? 2 : 4
      const brkVec  = brkVecSize === 2 ? child.readUInt16BE(brkHdr) : child.readUInt32BE(brkHdr)
      const brkData = child.slice(brkHdr + brkVecSize, brkLen)

      // Track whether the client uses Pathport short-vector format (brkHdr=3 → 2-byte vectors).
      // We must respond in the SAME format so the client can parse our reply.
      result.pathportFormat = (brkHdr === 3)

      if (brkVec === VECTOR_BROKER_CONNECT) {
        result.type = 'broker_connect'
        // Header: Scope(63) + E133Ver(2) + SearchDomain(231) + Flags(1) = 297 bytes
        if (brkData.length >= 297) {
          result.scope   = brkData.slice(0, 63).toString('utf8').replace(/\0/g, '').trim()
          result.flags   = brkData[296]
        }
        // Client Entry PDU begins at offset 297
        // Attempt 25: Client Entry PDU always uses 4-byte vectors, even when the
        // enclosing broker PDU uses 2-byte vectors (Pathport format).  Using 2-byte
        // vectors here produces a Client Entry CID that does NOT match the root CID,
        // which means we echo the wrong UID back in BROKER_CONNECT_REPLY.  The Pathport
        // validates the echoed UID and disconnects immediately when it is wrong.
        // Using 4-byte vectors gives a CID that matches the root CID (correct per E1.33).
        if (brkData.length > 297) {
          const entryBuf = brkData.slice(297)
          if (entryBuf.length >= 4) {
            const { length: eLen, headerSize: eHdr } = parseFlagsLen(entryBuf, 0)
            const eVecSize = 4  // always 4-byte vector for Client Entry PDU (Attempt 25)
            const eData = entryBuf.slice(eHdr + eVecSize, eLen)  // skip flags+length + vector
            if (eData.length >= 23) {
              result.clientCIDBuf  = eData.slice(0, 16)
              result.clientCID     = result.clientCIDBuf.toString('hex')
              result.clientUIDBuf  = eData.slice(16, 22)
              result.clientUID     = result.clientUIDBuf.toString('hex').toUpperCase()
              result.clientType    = eData[22]   // 0x01=Controller 0x02=Device
              result.uidStr        = uidStr(result.clientUIDBuf)
              // Diagnostic: verify Client Entry CID matches root CID (they must be equal per E1.33)
              const rootCIDhex = result.cidBuf ? result.cidBuf.toString('hex') : '(none)'
              const cidMatch = result.cidBuf && result.clientCIDBuf.equals(result.cidBuf)
              console.log(`[Broker] ClientEntry CID=${result.clientCID} rootCID=${rootCIDhex} match=${cidMatch} UID=${result.clientUID} type=${result.clientType}`)
            }
          }
        }
      } else if (brkVec === VECTOR_BROKER_NULL) {
        result.type = 'broker_null'
      } else if (brkVec === VECTOR_BROKER_DISCONNECT) {
        result.type = 'broker_disconnect'
        if (brkData.length >= 2) result.disconnectReason = brkData.readUInt16BE(0)
      } else if (brkVec === VECTOR_BROKER_FETCH_CLIENT_LIST) {
        result.type = 'broker_fetch_client_list'
      } else {
        result.type = `broker_unknown_${brkVec}`
      }
    }

    // ── RPT layer ───────────────────────────────────────────────────────────
    if (rootVec === VECTOR_ROOT_RPT && child.length >= 7) {
      const { length: rptLen, headerSize: rptHdr } = parseFlagsLen(child, 0)
      // RPT PDU vector is ALWAYS 4 bytes (E1.33 §7.5.1), regardless of FL encoding.
      // Spec framing (rptHdr=3) has a 21-byte header (trailing reserved byte);
      // legacy rdmnet.js framing (rptHdr=2) uses a 20-byte header.
      const specFrame = rptHdr === 3
      const rptVec  = child.readUInt32BE(rptHdr)
      const rptBody = child.slice(rptHdr + 4, rptLen)
      const rptHeaderLen = specFrame ? 21 : 20

      if (rptBody.length >= rptHeaderLen) {
        result.srcUID      = rptBody.slice(0, 6)
        result.srcEndpoint = rptBody.readUInt16BE(6)
        result.destUID     = rptBody.slice(8, 14)
        result.destEndpoint= rptBody.readUInt16BE(14)
        result.seqNum      = rptBody.readUInt32BE(16)
        const payload      = rptBody.slice(rptHeaderLen)

        if (rptVec === VECTOR_RPT_NOTIFICATION && payload.length >= 4) {
          result.type = 'rpt_notification'
          if (specFrame) {
            // Notification PDU (3B FL + 4B vector) wrapping one or more RDM Command
            // PDUs (3B FL + 1B vector 0xCC + RDM message minus start code).
            // E1.33 §7.5.3: a notification for a completed command contains BOTH the
            // original command (echo) and its response.  We must return the RESPONSE
            // (command class is odd: GET_RESPONSE=0x21 etc.), not the echo.
            const { length: nLen, headerSize: nHdr } = parseFlagsLen(payload, 0)
            let off = nHdr + 4
            let firstRdm = null, responseRdm = null
            while (off + 4 <= nLen && off + 4 <= payload.length) {
              const { length: cLen, headerSize: cHdr } = parseFlagsLen(payload, off)
              if (cLen < cHdr + 2 || off + cLen > nLen) break
              const startCode = payload[off + cHdr]
              const rdmBody   = payload.slice(off + cHdr + 1, off + cLen)
              // Re-prepend the start code so downstream RDM parsers see a full packet
              const full = Buffer.concat([Buffer.from([startCode]), rdmBody])
              if (!firstRdm) firstRdm = full
              // Full RDM packet layout: command class lives at byte 20
              if (full.length > 20 && (full[20] & 0x01)) responseRdm = full
              off += cLen
            }
            result.rdmData = responseRdm || firstRdm
          } else {
            // Legacy single-layer framing (rdmnet.js): full RDM packet in PDU data
            const { length: innerLen, headerSize: innerHdr } = parseFlagsLen(payload, 0)
            result.rdmData = payload.slice(innerHdr + 4, innerLen)
          }
        } else if (rptVec === VECTOR_RPT_STATUS) {
          result.type = 'rpt_status'
          if (payload.length >= 4) {
            const { headerSize: stHdr } = parseFlagsLen(payload, 0)
            // Status PDU vector is the 2-byte status code (E1.33 §7.5.4);
            // legacy rdmnet.js frames carry a 4-byte code.
            result.statusCode = specFrame ? payload.readUInt16BE(stHdr) : payload.readUInt32BE(stHdr)
          }
        } else if (rptVec === VECTOR_RPT_REQUEST) {
          result.type = 'rpt_request'
        }
      }
    }

    return result.type ? result : null
  } catch (_) { return null }
}

// ─── mDNS Advertisement ───────────────────────────────────────────────────────

/**
 * Return true if remoteIP is on the same subnet as localIP given netmask.
 * Used to suppress mDNS responses from sockets that are NOT on the same
 * subnet as the querier — when multiple sockets all bind to 0.0.0.0:5353
 * with reuseAddr, macOS delivers each multicast query to ALL sockets, not
 * just the one whose interface the query arrived on.  Without this guard
 * every Pathport query triggers 4 conflicting SRV responses (one per NIC),
 * confusing the Pathport firmware into never connecting.
 */
function isSameSubnet(localIP, remoteIP, netmask) {
  try {
    const l = localIP.split('.').map(Number)
    const r = remoteIP.split('.').map(Number)
    const m = netmask.split('.').map(Number)
    return l.every((octet, i) => (octet & m[i]) === (r[i] & m[i]))
  } catch (_) {
    return false
  }
}

/**
 * Build a DNS name in wire format (length-prefixed labels).
 * e.g. "_rdmnet._tcp.local" → \x07_rdmnet\x04_tcp\x05local\x00
 */
function encodeDNSName(name) {
  const bufs = []
  for (const label of name.split('.')) {
    if (!label.length) continue
    const l = Buffer.alloc(1 + label.length)
    l[0] = label.length
    Buffer.from(label, 'ascii').copy(l, 1)
    bufs.push(l)
  }
  bufs.push(Buffer.from([0x00]))
  return Buffer.concat(bufs)
}

function buildDNSRecord(name, type, ttl, rdata, cacheFlush = true) {
  // name: wire-format Buffer; class=IN(1).
  // Per RFC 6762 §10.2, PTR records are "shared" and MUST NOT set cache-flush;
  // SRV, TXT, A records are "unique" and SHOULD set cache-flush.
  const classValue = cacheFlush ? 0x8001 : 0x0001
  const r = Buffer.alloc(name.length + 10 + rdata.length)
  name.copy(r, 0)
  r.writeUInt16BE(type, name.length)
  r.writeUInt16BE(classValue, name.length + 2)
  r.writeUInt32BE(ttl, name.length + 4)
  r.writeUInt16BE(rdata.length, name.length + 8)
  rdata.copy(r, name.length + 10)
  return r
}

/**
 * Build a complete mDNS announcement for _rdmnet._tcp.local.
 * Sends: PTR (service type → instance), SRV (instance → host:port),
 *        TXT (empty properties), A (host → IP).
 */
// buildMDNSAnnouncement is superseded by buildSubtypePTRResponse which includes
// both the main PTR and subtype PTR records and uses the correct system hostname.
// Kept here as a thin wrapper for backward compatibility.
function buildMDNSAnnouncement(localIP, cidBuf, uidBuf) {
  return buildSubtypePTRResponse(localIP, cidBuf, uidBuf)
}

/**
 * Return the per-interface mDNS hostname for a given local IP.
 * e.g. 192.168.1.250 → "rdmexplorer-192-168-1-250.local"
 *
 * WHY per-interface instead of the system hostname:
 *   Using os.hostname() (e.g. Yoshis-MacBook-Pro-2.local) causes problems because
 *   mDNSResponder owns that name and will answer A-record queries for it — but it
 *   may answer with the WRONG interface IP (e.g. 10.0.5.169 on en0 instead of
 *   192.168.1.250 on en12).  If the Pathport resolves our SRV target to 10.0.5.169
 *   it will try to TCP connect to a subnet it can't reach, silently fail, and never
 *   connect to the broker.
 *
 *   Using a per-interface hostname means:
 *   - mDNSResponder has no record for it → can't interfere
 *   - Only OUR mDNS socket on that interface responds to A queries for it
 *   - A record always resolves to exactly the right IP
 */
function brokerHostnameForIP(localIP) {
  return 'rdmexplorer-' + localIP.replace(/\./g, '-') + '.local'
}

/**
 * Build a DNS-SD response to a _default._sub._rdmnet._tcp.local PTR browse query.
 * This is the subtype PTR that Pathport firmware queries to find brokers in the
 * "default" scope (per E1.33 §9.3).
 *
 * Uses a per-interface hostname (e.g. rdmexplorer-192-168-1-250.local) so that
 * A-record queries for the SRV target can ONLY be answered by us — not by
 * mDNSResponder, which might return the wrong interface IP.
 *
 * Uses DNS name pointer compression (RFC 1035 §4.1.4) so the response is
 * ~190 bytes instead of ~350 bytes.  Embedded firmware often has fixed-size
 * mDNS parse buffers (~256 bytes); the uncompressed form was getting silently
 * discarded by Pathport firmware.
 *
 * Response layout:
 *   ANSWER (1):     PTR  _default._sub._rdmnet._tcp.local → RDM Explorer._rdmnet._tcp.local
 *   ADDITIONAL (4): SRV  RDM Explorer._rdmnet._tcp.local  → rdmexplorer-<ip>.local:5569
 *                   TXT  RDM Explorer._rdmnet._tcp.local  → E133Vers=1 E133Scope=default
 *                   PTR  _rdmnet._tcp.local               → RDM Explorer._rdmnet._tcp.local
 *                   A    rdmexplorer-<ip>.local            → <localIP>
 *
 * Pointer safety invariant: ALL compression pointers point to NAME fields, never RDATA.
 *   Subtype PTR RDATA:  written with writeNameNoCompress → NOT registered in nameTable.
 *   SRV comes FIRST in ADDITIONAL, registering fullSvc at its OWNER (NAME field).
 *   TXT, main PTR and A then use pointers to that NAME-field offset.
 *   RFC 1035 is technically permissive about pointer targets, but many embedded firmware
 *   parsers (including some Pathway Pathport firmware versions) silently refuse to follow
 *   pointers that land inside another record's RDATA section.
 *
 * Packet size: ~250 bytes (well within the ~256-byte firmware mDNS parse buffer).
 */
function buildSubtypePTRResponse(localIP, cidBuf, uidBuf) {
  const sysHost = brokerHostnameForIP(localIP)
  const fullSvc = `${SERVICE_NAME}._rdmnet._tcp.local`
  const svcType = '_rdmnet._tcp.local'
  const subType = '_default._sub._rdmnet._tcp.local'

  // Compressed DNS packet builder.
  // nameTable maps canonical name string → byte offset in packet, enabling
  // RFC 1035 §4.1.4 pointer compression (0xC000 | offset).
  const buf = Buffer.alloc(512)
  let p = 12  // start after 12-byte header (filled in at the end)
  const nameTable = new Map()

  // Write a DNS name with pointer compression.
  // First occurrence of each name/suffix is written in full and registered.
  // Subsequent occurrences are replaced with a 2-byte 0xC0xx pointer.
  function writeName(name) {
    const labels = name.split('.').filter(l => l.length > 0)
    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join('.')
      if (nameTable.has(suffix)) {
        const ptr = nameTable.get(suffix)
        buf[p++] = 0xC0 | (ptr >> 8)
        buf[p++] = ptr & 0xFF
        return  // pointer terminates the name
      }
      nameTable.set(suffix, p)  // register this suffix at current position
      const label = labels[i]
      buf[p++] = label.length
      buf.write(label, p, 'ascii')
      p += label.length
    }
    buf[p++] = 0  // null root label (no pointer used)
  }

  // Write a DNS name WITHOUT compression pointers.
  // Used for RDATA fields where compression is forbidden by spec:
  //   RFC 2782 §4: "name compression is not to be used" in SRV Target.
  //
  // Intentionally does NOT register suffixes in nameTable.  If we registered
  // the SRV Target here, the subsequent A record owner-name would compress to
  // a pointer into SRV RDATA (e.g. 0xC063 pointing to offset 99).  Embedded
  // firmware parsers often refuse to follow pointers that land inside RDATA —
  // they only follow pointers into the answer/additional record NAME fields.
  // By not registering, writeName() later writes the A owner as
  // "\x19rdmexplorer-...\xC0\x27" (label + pointer-to-'local' at offset 39,
  // which IS a proper name field), keeping all pointers in safe territory.
  function writeNameNoCompress(name) {
    const labels = name.split('.').filter(l => l.length > 0)
    for (const label of labels) {
      buf[p++] = label.length
      buf.write(label, p, 'ascii')
      p += label.length
    }
    buf[p++] = 0
  }

  // Write a complete DNS resource record.
  // rdataWriter() is called to write the rdata bytes; rdlen is back-filled.
  function writeRR(name, type, cacheFlush, rdataWriter) {
    writeName(name)
    buf.writeUInt16BE(type, p);                      p += 2
    buf.writeUInt16BE(cacheFlush ? 0x8001 : 0x0001, p); p += 2  // class IN ± cache-flush
    buf.writeUInt32BE(MDNS_TTL, p);                  p += 4
    const rdlenPos = p;                              p += 2  // rdlen placeholder
    const rdStart = p
    rdataWriter()
    buf.writeUInt16BE(p - rdStart, rdlenPos)  // back-fill rdlen
  }

  // ANSWER (1 record): subtype PTR
  // Use writeNameNoCompress for the RDATA so that 'RDM Explorer._rdmnet._tcp.local'
  // is NOT registered in nameTable here (offset 56 = RDATA, not a NAME field).
  // If registered here, subsequent SRV/TXT owners would use pointer 0xC038 → offset 56
  // which lands inside RDATA — some Pathport firmware parsers refuse such pointers.
  // By deferring registration until the SRV owner below (a proper NAME field), all
  // subsequent compression pointers are guaranteed to land in NAME fields only.
  writeRR(subType, 12, false, () => {
    writeNameNoCompress(fullSvc)  // PTR target: fully expanded, does NOT touch nameTable
  })

  // ADDITIONAL record 1: SRV — comes FIRST so fullSvc is registered in its OWNER NAME field.
  // All subsequent records (TXT, main PTR) that use fullSvc will then get a pointer that
  // points to this SRV owner (a NAME field), not to the subtype PTR RDATA above.
  // RFC 2782 §4: "name compression is not to be used" for the SRV Target field.
  writeRR(fullSvc, 33, true, () => {
    buf.writeUInt16BE(0, p); p += 2  // priority
    buf.writeUInt16BE(0, p); p += 2  // weight
    buf.writeUInt16BE(RDMNET_PORT, p); p += 2  // port
    writeNameNoCompress(sysHost)  // target: full uncompressed hostname per RFC 2782
  })

  // ADDITIONAL record 2: TXT (owner uses pointer to SRV owner NAME field ← safe)
  // E1.33 §9.3.3.1 — ALL six keys are required; Pathport firmware validates
  // their presence before initiating a TCP connection to the broker.
  writeRR(fullSvc, 16, true, () => {
    // E1.33 §9.3.3.1 Table 9-4 / ETC RDMnet reference implementation:
    // CID is a 32-char hex string with NO dashes (etcpal_uuid_to_string, hyphens stripped).
    const cidHex = cidBuf ? cidBuf.toString('hex') : '00000000000000000000000000000000'
    const uidHex = uidBuf ? uidBuf.toString('hex') : '7ff000000001'
    const txtEntries = [
      'TxtVers=1',           // must be first per E1.33
      'E133Scope=default',   // scope this broker serves
      'E133Vers=1',          // E1.33 protocol version
      `CID=${cidHex}`,       // broker CID (16 bytes as 32 hex chars, no dashes)
      `UID=${uidHex}`,       // broker UID (6 bytes as 12 hex chars)
      'Model=RDM-Explorer',  // broker model name
      'Manuf=OpenSource',    // broker manufacturer
    ]
    for (const s of txtEntries) {
      buf[p++] = s.length
      buf.write(s, p, 'ascii')
      p += s.length
    }
  })

  // ADDITIONAL record 3: main type PTR (comes AFTER SRV so its RDATA pointer is backward)
  // RDATA uses pointer to SRV owner NAME field — safe backward pointer ✓
  writeRR(svcType, 12, false, () => {
    writeName(fullSvc)
  })

  // ADDITIONAL record 4: A (owner uses label + pointer to 'local' in PTR QNAME — NAME field ✓)
  writeRR(sysHost, 1, true, () => {
    for (const octet of localIP.split('.').map(Number)) buf[p++] = octet
  })

  // Fill in DNS header
  buf.writeUInt16BE(0,      0)   // ID = 0 (mDNS)
  buf.writeUInt16BE(0x8400, 2)   // Flags: QR=1 AA=1
  buf.writeUInt16BE(0,      4)   // QDCOUNT = 0
  buf.writeUInt16BE(1,      6)   // ANCOUNT = 1 (subtype PTR only in ANSWER)
  buf.writeUInt16BE(0,      8)   // NSCOUNT = 0
  buf.writeUInt16BE(4,     10)   // ARCOUNT = 4

  return buf.slice(0, p)
}

/**
 * Check if a raw DNS message is a query for _rdmnet._tcp.local.
 */
function isMDNSQueryForRDMnet(msg) {
  try {
    if (msg.length < 12) return false
    const flags = msg.readUInt16BE(2)
    if (flags & 0x8000) return false   // it's a response, not a query
    const qdCount = msg.readUInt16BE(4)
    if (qdCount === 0) return false
    // Quick text search — sufficient for our purpose
    return msg.toString('ascii').includes('_rdmnet')
  } catch (_) { return false }
}

/**
 * Extract the query name(s) from a DNS query message.
 * Returns array of "name TYPE" strings.
 */
function extractQueryNames(msg) {
  try {
    if (msg.length < 12) return []
    const qdCount = msg.readUInt16BE(4)
    const names = []
    let off = 12
    for (let q = 0; q < qdCount && off < msg.length; q++) {
      let name = ''
      while (off < msg.length) {
        const len = msg[off]
        if (len === 0) { off++; break }
        if ((len & 0xC0) === 0xC0) { off += 2; break }
        if (name.length > 0) name += '.'
        name += msg.slice(off + 1, off + 1 + len).toString('ascii')
        off += 1 + len
      }
      if (off + 4 <= msg.length) {
        const qtype = msg.readUInt16BE(off)
        const typeStr = qtype === 12 ? 'PTR' : qtype === 33 ? 'SRV' : qtype === 1 ? 'A' :
                       qtype === 28 ? 'AAAA' : qtype === 16 ? 'TXT' : qtype === 255 ? 'ANY' : `type${qtype}`
        names.push(`${name} ${typeStr}`)
        off += 4  // skip QTYPE(2) + QCLASS(2)
      } else {
        if (name) names.push(name)
      }
    }
    return names
  } catch (_) { return [] }
}

/**
 * Check if a raw DNS message is a query (not for _rdmnet) — used to detect
 * follow-up A-record queries from Pathports trying to resolve our hostname.
 * Returns a description string if it's a relevant query, null otherwise.
 */
function describeOtherMDNSQuery(msg) {
  try {
    if (msg.length < 12) return null
    const flags = msg.readUInt16BE(2)
    if (flags & 0x8000) return null   // response, not query
    const qdCount = msg.readUInt16BE(4)
    if (qdCount === 0) return null
    // Already handled by isMDNSQueryForRDMnet
    const ascii = msg.toString('ascii')
    if (ascii.includes('_rdmnet')) return null
    // Look for hostname-related queries (our hostname or rdmexplorer)
    const lower = ascii.toLowerCase()
    if (lower.includes('rdmexplorer') || lower.includes(os.hostname().split('.')[0].toLowerCase())) {
      // Extract query name
      let name = ''
      let off = 12
      while (off < msg.length) {
        const len = msg[off]
        if (len === 0) break
        if ((len & 0xC0) === 0xC0) break
        if (name.length > 0) name += '.'
        name += msg.slice(off + 1, off + 1 + len).toString('ascii')
        off += 1 + len
      }
      if (off + 1 < msg.length) {
        const qtype = msg.readUInt16BE(off + 1)
        const typeStr = qtype === 1 ? 'A' : qtype === 28 ? 'AAAA' : qtype === 255 ? 'ANY' : `type${qtype}`
        return `${name} ${typeStr}`
      }
      return name
    }
    return null
  } catch (_) { return null }
}

/**
 * Check if a raw DNS message is an A-record query for a specific hostname.
 * Used to detect when a Pathport is resolving the SRV target we advertised.
 * @param {Buffer} msg   raw DNS/mDNS message
 * @param {string} hostname  e.g. "rdmexplorer-192-168-1-250.local"
 * @returns {boolean}
 */
function isAQueryForHostname(msg, hostname) {
  try {
    if (msg.length < 12) return false
    if (msg.readUInt16BE(2) & 0x8000) return false  // it's a response
    if (msg.readUInt16BE(4) === 0) return false       // no questions
    // Quick text check first (cheap)
    if (!msg.toString('ascii').toLowerCase().includes(hostname.split('.')[0].toLowerCase())) return false
    // Parse questions properly
    const qdCount = msg.readUInt16BE(4)
    let off = 12
    for (let q = 0; q < qdCount && off < msg.length; q++) {
      let name = ''
      while (off < msg.length) {
        const len = msg[off]
        if (len === 0) { off++; break }
        if ((len & 0xC0) === 0xC0) { off += 2; break }
        if (name.length > 0) name += '.'
        name += msg.slice(off + 1, off + 1 + len).toString('ascii')
        off += 1 + len
      }
      if (off + 4 <= msg.length) {
        const qtype = msg.readUInt16BE(off)
        off += 4
        if (qtype === 1 /* A */ && name.toLowerCase() === hostname.toLowerCase()) return true
        if (qtype === 255 /* ANY */ && name.toLowerCase() === hostname.toLowerCase()) return true
      }
    }
    return false
  } catch (_) { return false }
}

/**
 * Build a minimal mDNS response containing a single A record.
 * Used to answer A-record queries for our per-interface broker hostname.
 * @param {string} hostname  e.g. "rdmexplorer-192-168-1-250.local"
 * @param {string} ip        e.g. "192.168.1.250"
 * @returns {Buffer}
 */
function buildAResponse(hostname, ip) {
  const nameBuf = encodeDNSName(hostname)
  const aRdata  = Buffer.from(ip.split('.').map(Number))
  const aRec    = buildDNSRecord(nameBuf, 1, MDNS_TTL, aRdata, true)  // A — unique, cache-flush

  const hdr = Buffer.alloc(12)
  hdr.writeUInt16BE(0,      0)   // ID = 0
  hdr.writeUInt16BE(0x8400, 2)   // QR=1 AA=1
  hdr.writeUInt16BE(0,      4)   // QDCOUNT = 0
  hdr.writeUInt16BE(1,      6)   // ANCOUNT = 1
  hdr.writeUInt16BE(0,      8)   // NSCOUNT = 0
  hdr.writeUInt16BE(0,     10)   // ARCOUNT = 0

  return Buffer.concat([hdr, aRec])
}

/**
 * Check if a raw DNS message is a response mentioning _rdmnet._tcp.
 * If so, extract any A records (type=1) to see what IP is being advertised.
 * Returns null if not an rdmnet response, or { hostname, ip, port } if parseable.
 */
function parseMDNSResponseForRDMnet(msg) {
  try {
    if (msg.length < 12) return null
    const flags = msg.readUInt16BE(2)
    if (!(flags & 0x8000)) return null  // not a response
    if (!msg.toString('ascii').includes('_rdmnet')) return null

    const result = { aRecords: [], srvTarget: null, srvPort: null, ptrTargets: [] }

    // Walk all resource records looking for A (type=1) and SRV (type=33) records
    const qdCount = msg.readUInt16BE(4)
    const anCount = msg.readUInt16BE(6)
    const nsCount = msg.readUInt16BE(8)
    const arCount = msg.readUInt16BE(10)
    const totalRR = anCount + nsCount + arCount

    // Skip past the question section
    let offset = 12
    for (let q = 0; q < qdCount && offset < msg.length; q++) {
      // Skip name
      while (offset < msg.length) {
        const len = msg[offset]
        if (len === 0) { offset++; break }
        if ((len & 0xC0) === 0xC0) { offset += 2; break }  // pointer
        offset += 1 + len
      }
      offset += 4  // skip QTYPE(2) + QCLASS(2)
    }

    // Parse resource records
    for (let rr = 0; rr < totalRR && offset < msg.length; rr++) {
      // Skip name
      const nameStart = offset
      while (offset < msg.length) {
        const len = msg[offset]
        if (len === 0) { offset++; break }
        if ((len & 0xC0) === 0xC0) { offset += 2; break }
        offset += 1 + len
      }

      if (offset + 10 > msg.length) break
      const rrType   = msg.readUInt16BE(offset)
      const rrClass  = msg.readUInt16BE(offset + 2) & 0x7FFF  // mask cache-flush bit
      const rrTTL    = msg.readUInt32BE(offset + 4)
      const rdLen    = msg.readUInt16BE(offset + 8)
      offset += 10

      if (offset + rdLen > msg.length) break

      if (rrType === 1 && rdLen === 4) {
        // A record — IPv4 address
        const ip = `${msg[offset]}.${msg[offset+1]}.${msg[offset+2]}.${msg[offset+3]}`
        result.aRecords.push(ip)
      } else if (rrType === 33 && rdLen >= 7) {
        // SRV record — priority(2) + weight(2) + port(2) + target(name)
        result.srvPort = msg.readUInt16BE(offset + 4)
        // Parse target hostname
        let tgt = ''
        let tOff = offset + 6
        while (tOff < offset + rdLen) {
          const len = msg[tOff]
          if (len === 0) break
          if ((len & 0xC0) === 0xC0) {
            // pointer — follow it
            const ptr = ((len & 0x3F) << 8) | msg[tOff + 1]
            let pOff = ptr
            while (pOff < msg.length) {
              const pLen = msg[pOff]
              if (pLen === 0) break
              if ((pLen & 0xC0) === 0xC0) break  // nested pointer — stop
              if (tgt.length > 0) tgt += '.'
              tgt += msg.slice(pOff + 1, pOff + 1 + pLen).toString('ascii')
              pOff += 1 + pLen
            }
            break
          }
          if (tgt.length > 0) tgt += '.'
          tgt += msg.slice(tOff + 1, tOff + 1 + len).toString('ascii')
          tOff += 1 + len
        }
        result.srvTarget = tgt
      } else if (rrType === 12) {
        // PTR record — parse the target name from rdata
        let ptr = ''
        let pOff = offset
        while (pOff < offset + rdLen) {
          const len = msg[pOff]
          if (len === 0) break
          if ((len & 0xC0) === 0xC0) {
            const ptrOff = ((len & 0x3F) << 8) | msg[pOff + 1]
            let ppOff = ptrOff
            while (ppOff < msg.length) {
              const pLen = msg[ppOff]
              if (pLen === 0) break
              if ((pLen & 0xC0) === 0xC0) break
              if (ptr.length > 0) ptr += '.'
              ptr += msg.slice(ppOff + 1, ppOff + 1 + pLen).toString('ascii')
              ppOff += 1 + pLen
            }
            break
          }
          if (ptr.length > 0) ptr += '.'
          ptr += msg.slice(pOff + 1, pOff + 1 + len).toString('ascii')
          pOff += 1 + len
        }
        if (ptr) result.ptrTargets.push(ptr)
      }

      offset += rdLen
    }

    return (result.aRecords.length > 0 || result.srvTarget || result.ptrTargets.length > 0) ? result : null
  } catch (_) { return null }
}

// ─── RDMnetBroker Class ───────────────────────────────────────────────────────

class RDMnetBroker extends EventEmitter {
  constructor() {
    super()
    // Broker identity (CID + UID) is PERSISTED across app restarts.
    // E1.33 clients (Pathport firmware) cache the advertised broker identity in
    // their mDNS cache for up to 75 minutes. If a restarted broker shows up at
    // the same name/host/port with a DIFFERENT CID, the firmware wedges in a
    // browse-but-never-reconnect state until power-cycled. With a stable
    // identity, a restart looks like a brief TCP blip and they reconnect.
    const ident   = loadOrCreateBrokerIdentity()
    this.cid      = ident.cid
    this.uid      = ident.uid
    this.server   = null
    this.mdnsSock   = null   // kept for compat — unused after per-iface refactor
    this._mdnsSocks = []     // [ { ip, sock } ] — one socket per local interface
    this._dnsSdProcess   = null  // legacy compat — first dns-sd child process
    this._dnsSdProcesses = []   // [ { child, ip } ] — one dns-sd -P per interface (macOS only)
    this._dnsSDActive    = false // true when dns-sd is handling mDNS (macOS) — suppresses hand-rolled responses
    this._mdnsQueriers   = new Map()  // IP → { firstSeen, queryCount } — track devices querying us
    this._clients = new Map()   // socket → ClientState
    this._pending = new Map()   // seqNum → { timer, resolve, socketRef }
    this._seq     = 1
    // macOS Local Network privacy fallback: set once we have detected that direct
    // mDNS sends are blocked (EHOSTUNREACH) and switched to dns-sd/mDNSResponder.
    this._dnsSdFallbackTried = false
    this._keepaliveTimer  = null
    this._mdnsReannounce  = null  // periodic mDNS re-announce timer
    this.running  = false
    this.port     = RDMNET_PORT
    this.mDNSIPs  = []         // IPs we are advertising on (set in _startMDNS)
    this.mDNSError = null      // set if ALL mDNS sockets fail to bind

    // Startup log buffer — stores log messages emitted before any listener
    // subscribes (because the broker starts at module load time, before the
    // first Scanner is constructed).  Flushed when the first 'log' listener
    // attaches via on('log', ...).
    this._startupLogs = []
  }

  // Override on() so we can flush buffered startup logs to the first listener.
  on(event, listener) {
    super.on(event, listener)
    if (event === 'log' && this._startupLogs.length > 0) {
      const buffered = this._startupLogs.splice(0)
      setImmediate(() => buffered.forEach(msg => this.emit('log', msg)))
    }
    return this
  }

  // Internal: emit a log event, buffering it if nobody is listening yet.
  _log(msg) {
    if (this.listenerCount('log') > 0) {
      this.emit('log', msg)
    } else {
      this._startupLogs.push(msg)
    }
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Start the embedded broker.  Creates TCP server on port 5569, advertises
   * via mDNS, and starts keepalive timer.
   * @returns {Promise<void>}
   */
  async start() {
    if (this.running) return

    // macOS: sweep orphaned `dns-sd -P RDM-Explorer` registrations left behind by
    // previous instances that were killed hard (crash, force-quit). A stale
    // registration keeps advertising our service name with a dead port through
    // mDNSResponder, poisoning Pathport discovery with conflicting answers.
    // Matching on our service name means we can only ever kill our own helpers.
    if (process.platform === 'darwin') {
      try {
        const { execFileSync } = require('child_process')
        execFileSync('pkill', ['-f', 'dns-sd -P RDM-Explorer'], { stdio: 'ignore' })
        this._log('[RDMnet Broker] Cleared stale dns-sd registrations from a previous run')
      } catch (_) { /* pkill exits 1 when nothing matched — the normal case */ }
    }

    await this._startTCPServer()
    this._startMDNS()
    this._startKeepalive()
    this.running = true

    // On macOS, check firewall status and log it — a blocking firewall is the #1
    // reason Pathports can see the broker via mDNS but can't TCP connect.
    if (process.platform === 'darwin') this._checkFirewall()
  }

  /**
   * Stop the broker and close all connections.
   */
  stop() {
    if (this._keepaliveTimer)  { clearInterval(this._keepaliveTimer);  this._keepaliveTimer  = null }
    if (this._mdnsReannounce)  { clearInterval(this._mdnsReannounce);  this._mdnsReannounce  = null }
    // Kill all dns-sd processes (one per interface)
    if (this._dnsSdProcesses) {
      for (const { child } of this._dnsSdProcesses) { try { child.kill() } catch (_) {} }
      this._dnsSdProcesses = []
    }
    if (this._dnsSdProcess) { try { this._dnsSdProcess.kill() } catch (_) {} this._dnsSdProcess = null }
    this._dnsSDActive = false
    this._dnsSdFallbackTried = false
    this._mdnsQueriers.clear()
    if (this.server)           { try { this.server.close() } catch (_) {} this.server = null }
    for (const { sock } of this._mdnsSocks) { try { sock.close() } catch (_) {} }
    this._mdnsSocks = []
    this.mdnsSock = null
    for (const [sock] of this._clients) { try { sock.destroy() } catch (_) {} }
    this._clients.clear()
    // Reject all pending RDM promises
    for (const [, p] of this._pending) { clearTimeout(p.timer); p.resolve(null) }
    this._pending.clear()
    this.running = false
  }

  /**
   * Return IPs that queried the broker via mDNS in the last few minutes but are
   * not currently TCP-connected — the "browse-but-won't-connect" wedge signature.
   */
  getStuckQueriers(windowMs = 5 * 60 * 1000) {
    const connected = new Set()
    for (const [sock, client] of this._clients) {
      if (client.connected && sock.remoteAddress) {
        connected.add(sock.remoteAddress.replace('::ffff:', ''))
      }
    }
    const now = Date.now()
    const stuck = []
    for (const [ip, q] of this._mdnsQueriers) {
      const recent = q.lastSeen ? (now - q.lastSeen) < windowMs : true
      if (!connected.has(ip) && recent) stuck.push(ip)
    }
    return stuck
  }

  /**
   * Return all connected RPT Device (gateway) clients.
   * @returns {Array<{ cidHex: string, cidBuf: Buffer, uid: string, ip: string }>}
   */
  getConnectedGateways() {
    const gateways = []
    for (const [sock, client] of this._clients) {
      if (client.connected && client.clientType === CLIENT_TYPE_DEVICE) {
        gateways.push({
          cidHex: client.cidBuf.toString('hex'),
          cidBuf: client.cidBuf,
          uid:    client.uidStr,
          uidBuf: client.uidBuf,
          ip:     sock.remoteAddress,
        })
      }
    }
    return gateways
  }

  /**
   * Return RDM responders passively observed in a gateway's unsolicited RPT
   * notifications (Pathports background-poll their fixtures and stream the
   * responses to all connected controllers).
   * @param {Buffer} gatewayCIDBuf
   * @returns {Array<{ uidBuf: Buffer, endpoint: number, lastSeen: number }>}
   */
  getObservedResponders(gatewayCIDBuf) {
    for (const [, client] of this._clients) {
      if (client.connected && client.cidBuf && client.cidBuf.equals(gatewayCIDBuf)) {
        return client.observedResponders ? [...client.observedResponders.values()] : []
      }
    }
    return []
  }

  /**
   * Send an RDM command to a device via an RPT Gateway.
   *
   * @param {Buffer}  gatewayCIDBuf  16-byte CID of the target gateway
   * @param {Buffer}  destUID        6-byte destination UID (device or broadcast)
   * @param {number}  destEndpoint   0 = gateway itself; 1+ = physical port/endpoint
   * @param {Buffer}  rdmPacket      Full RDM packet starting with 0xCC
   * @param {number}  [timeoutMs=600]
   * @returns {Promise<Buffer|null>}  RDM response payload, or null on timeout
   */
  sendRdm(gatewayCIDBuf, destUID, destEndpoint, rdmPacket, timeoutMs = 600) {
    return new Promise((resolve) => {
      // Find the socket and client record for this gateway
      let targetSock   = null
      let targetClient = null
      for (const [sock, client] of this._clients) {
        if (client.connected && client.cidBuf &&
            client.cidBuf.equals(gatewayCIDBuf)) {
          targetSock   = sock
          targetClient = client
          break
        }
      }
      if (!targetSock) return resolve(null)

      const seqNum = (this._seq++) >>> 0
      const pkt    = buildRPTRequest(this.cid, this.uid, destUID, destEndpoint, seqNum, rdmPacket,
                                     targetClient.pathportFormat, targetClient.effectiveVecSize || null)

      const timer = setTimeout(() => {
        this._pending.delete(seqNum)
        resolve(null)
      }, timeoutMs)

      this._pending.set(seqNum, { timer, resolve, socket: targetSock })

      try {
        targetSock.write(pkt)
      } catch (_) {
        clearTimeout(timer)
        this._pending.delete(seqNum)
        resolve(null)
      }
    })
  }

  // ─── TCP Server ─────────────────────────────────────────────────────────────

  _startTCPServer() {
    return new Promise((resolve, reject) => {
      this.server = net.createServer((socket) => this._handleConnection(socket))

      this.server.on('error', (err) => {
        if (!this.running) {
          // Startup failure
          reject(err)
        } else if (this.listenerCount('error') > 0) {
          this.emit('error', err)
        }
      })

      this.server.listen(RDMNET_PORT, '0.0.0.0', () => {
        this._log(`[RDMnet Broker] TCP server listening on 0.0.0.0:${RDMNET_PORT}`)
        resolve()
      })
    })
  }

  _handleConnection(socket) {
    const ip = socket.remoteAddress || '?'
    this._log(`[RDMnet Broker] TCP connection from ${ip}`)
    console.log(`[Broker] t=${Date.now()%100000} TCP connection from ${ip}`)  // visible in test log

    // Disable Nagle's algorithm so each socket.write() is sent as its own TCP segment.
    // This prevents BROKER_CONNECT_REPLY and BROKER_CONNECTED_CLIENT_LIST from being
    // coalesced into a single segment that Pathport firmware might not parse correctly.
    socket.setNoDelay(true)

    const client = {
      ip,
      cidBuf:     null,
      uidBuf:     null,
      uidStr:     null,
      clientType: null,
      connected:  false,
      buf:        Buffer.alloc(0),
    }

    this._clients.set(socket, client)

    socket.on('data', (chunk) => {
      // Rate-limit per-packet logging: Pathports background-poll their fixtures and
      // broadcast EVERY RDM response to all controllers — thousands of notifications
      // per second per gateway.  Logging each one froze the renderer (200k progress
      // events in a 19s scan, Session 45).  Log the first few chunks for diagnostics,
      // then go quiet; non-routine packet types are still always logged below.
      client._rxChunks = (client._rxChunks || 0) + 1
      if (client._rxChunks <= 8) {
        console.log(`[Broker] data from ${ip}: ${chunk.length}B hex=${chunk.toString('hex')}`)
        this._log(`[RDMnet Broker] data from ${ip}: ${chunk.length}B hex=${chunk.toString('hex').slice(0, 200)}`)
      }
      client.buf = Buffer.concat([client.buf, chunk])
      const { packets, remainder } = parseTCPStream(client.buf)
      client.buf = remainder
      if (packets.length === 0 && remainder.length > 0 && client._rxChunks <= 8) {
        console.log(`[Broker] parseTCPStream: ${remainder.length}B unparsed from ${ip}`)
      }
      for (const pkt of packets) {
        // Routine stream traffic (notifications, keepalives) is not logged per-packet.
        const routine = pkt.type === 'rpt_notification' || pkt.type === 'broker_null'
        if (!routine || client._rxChunks <= 8) {
          const cidInfo = pkt.clientCID ? ` CID=${pkt.clientCID.slice(0,8)}... UID=${pkt.clientUID}` : ''
          console.log(`[Broker] pkt from ${ip}: type=${pkt.type}${cidInfo}`)
          this._log(`[RDMnet Broker] pkt from ${ip}: type=${pkt.type}${cidInfo}`)
        }
        this._handlePacket(socket, client, pkt)
      }
    })

    socket.on('close', () => {
      // Use the local `client` reference (captured in closure) rather than _clients.get(socket),
      // because stop() calls _clients.clear() synchronously before async 'close' events fire,
      // which would otherwise produce misleading "was connected: ?" log messages.
      console.log(`[Broker] TCP close from ${ip} (was connected: ${client.connected})`)
      if (client.cidBuf) {
        this._log(`[RDMnet Broker] Client disconnected: ${client.ip} UID=${client.uidStr}`)
        this.emit('gatewayDisconnected', { ip: client.ip, cid: client.cidBuf.toString('hex'), uid: client.uidStr })
      }
      // Clean up any pending RDM promises for this socket
      for (const [seqNum, p] of this._pending) {
        if (p.socket === socket) {
          clearTimeout(p.timer)
          p.resolve(null)
          this._pending.delete(seqNum)
        }
      }
      this._clients.delete(socket)
    })

    socket.on('error', () => {
      try { socket.destroy() } catch (_) {}
    })
  }

  _handlePacket(socket, client, pkt) {
    switch (pkt.type) {
      case 'broker_connect':
        this._handleBrokerConnect(socket, client, pkt)
        break

      case 'broker_null':
        // Keepalive from client — echo one back in the same format.
        // Must use client.effectiveVecSize (auto-fallback aware) so the echo vector
        // matches what we used in BROKER_CONNECT_REPLY.  Using the wrong size here
        // would cause a Pathport disconnect after a successful handshake.
        try { socket.write(buildBrokerNull(this.cid, client.pathportFormat, client.effectiveVecSize || null)) } catch (_) {}
        break

      case 'broker_disconnect':
        if (pkt.disconnectReason !== undefined) {
          this._log(`[RDMnet Broker] BROKER_DISCONNECT from ${client.ip} (reason=${pkt.disconnectReason})`)
          console.log(`[Broker] BROKER_DISCONNECT from ${client.ip} reason=${pkt.disconnectReason}`)
        }
        try { socket.destroy() } catch (_) {}
        break

      case 'broker_fetch_client_list': {
        // Client explicitly requested the connected client list (E1.33 §6.3.x)
        const pdus = []
        for (const [existSock, existClient] of this._clients) {
          if (existSock !== socket && existClient.connected && existClient.cidBuf) {
            pdus.push(buildClientEntryPDU(existClient.cidBuf, existClient.uidBuf, existClient.clientType, client.pathportFormat))
          }
        }
        const ccl = buildConnectedClientList(this.cid, pdus, client.pathportFormat, client.effectiveVecSize || null)
        try { socket.write(ccl) } catch (_) {}
        this._log(`[RDMnet Broker] FETCH_CLIENT_LIST from ${client.ip} — sent CCL (${pdus.length} entries)`)
        break
      }

      case 'rpt_notification': {
        // Passive responder harvest: gateways (Pathports) stream unsolicited RPT
        // notifications containing RDM responses from fixtures they poll in the
        // background.  The RPT header's srcEndpoint + the inner RDM message's
        // source UID identify each live fixture — record them so the scanner can
        // discover devices even when the gateway does not support E1.37-7
        // ENDPOINT_LIST (Pathport fw 6.5.3 NACKs it).
        try {
          // Only harvest from RESPONSE messages (odd command class at byte 20) so we
          // never record the source UID of an echoed request (our own controller).
          // Also skip the 0x7FF0 prototype/dev manufacturer range (our UIDs).
          if (pkt.srcEndpoint > 0 && pkt.rdmData && pkt.rdmData.length >= 21 && pkt.rdmData[0] === 0xCC &&
              (pkt.rdmData[20] & 0x01) && pkt.rdmData.readUInt16BE(9) !== 0x7FF0) {
            const respUID = Buffer.from(pkt.rdmData.slice(9, 15))  // RDM source UID
            const uidHex  = respUID.toString('hex')
            if (!client.observedResponders) client.observedResponders = new Map()
            if (!client.observedResponders.has(uidHex)) {
              console.log(`[Broker] observed responder ${uidStr(respUID)} on ${client.ip} endpoint ${pkt.srcEndpoint}`)
              this._log(`[RDMnet Broker] Observed RDM responder ${uidStr(respUID)} on ${client.ip} endpoint ${pkt.srcEndpoint} (passive)`)
            }
            client.observedResponders.set(uidHex, { uidBuf: respUID, endpoint: pkt.srcEndpoint, lastSeen: Date.now() })
          }
        } catch (_) {}

        // RDM response coming back from the gateway.
        // Guard: under load, gateways can send the REQUEST ECHO and the RESPONSE
        // as separate notifications carrying the same sequence number.  Only a
        // response-class message (odd command class at byte 20) may resolve the
        // pending request — resolving on the echo loses the real response and
        // desyncs every subsequent read on that gateway.
        const isResponse = pkt.rdmData && pkt.rdmData.length > 20 && (pkt.rdmData[20] & 0x01)
        if (isResponse && pkt.seqNum !== undefined) {
          const pending = this._pending.get(pkt.seqNum)
          if (pending) {
            clearTimeout(pending.timer)
            this._pending.delete(pkt.seqNum)
            pending.resolve(pkt.rdmData)
          }
        }
        this.emit('rdmResponse', {
          ip:      client.ip,
          cid:     client.cidBuf ? client.cidBuf.toString('hex') : pkt.cid,
          rdmData: pkt.rdmData,
          seqNum:  pkt.seqNum,
        })
        break
      }

      case 'rpt_status': {
        // Gateway reporting an RPT-level error for one of our requests.
        const STATUS_NAMES = {
          0x0001: 'UNKNOWN_RPT_UID', 0x0002: 'RDM_TIMEOUT', 0x0003: 'RDM_INVALID_RESPONSE',
          0x0004: 'UNKNOWN_RDM_UID', 0x0005: 'UNKNOWN_ENDPOINT', 0x0006: 'BROADCAST_COMPLETE',
          0x0007: 'UNKNOWN_VECTOR', 0x0008: 'INVALID_MESSAGE', 0x0009: 'INVALID_COMMAND_CLASS',
        }
        const name = STATUS_NAMES[pkt.statusCode] || `0x${(pkt.statusCode || 0).toString(16)}`
        console.log(`[Broker] RPT_STATUS from ${client.ip}: ${name} (seq=${pkt.seqNum})`)
        if (pkt.seqNum !== undefined) {
          let pending = this._pending.get(pkt.seqNum)
          // Pathport fw 6.5.3 reports seq=0 in statuses for unroutable requests
          // (e.g. broadcast UIDs).  If exactly one request is pending, attribute
          // the status to it so the caller fails fast instead of burning the
          // full timeout.
          if (!pending && pkt.seqNum === 0 && this._pending.size === 1) {
            const [k, v] = this._pending.entries().next().value
            this._pending.delete(k)
            pending = v
          } else if (pending) {
            this._pending.delete(pkt.seqNum)
          }
          if (pending) {
            clearTimeout(pending.timer)
            pending.resolve(null)
          }
        }
        break
      }

      default:
        // Unknown packet type — ignore
        break
    }
  }

  /**
   * Broker-layer vector size for outgoing packets to a client.
   * E1.33-framed clients get the spec 2-byte vectors; legacy (rdmnet.js) clients
   * get 4-byte vectors.  (The Session-27 auto-fallback that flipped sizes after a
   * rejected REPLY was removed once the spec size was proven on real hardware.)
   */
  _getEffectiveVecSize(client) {
    return client.pathportFormat ? PATHPORT_OUTGOING_VEC_SIZE : 4
  }

  _handleBrokerConnect(socket, client, pkt) {
    // Record the gateway's identity from the Client Entry PDU
    if (pkt.clientCIDBuf) {
      client.cidBuf     = pkt.clientCIDBuf
      client.uidBuf     = pkt.clientUIDBuf || Buffer.alloc(6)
      client.uidStr     = pkt.uidStr       || '0000:00000000'
      // CLIENT_TYPE_DEVICE is 0x00 — must use an explicit undefined check, not `||`
      client.clientType = (typeof pkt.clientType === 'number') ? pkt.clientType : CLIENT_TYPE_DEVICE
    } else {
      // Fallback: use root-layer CID as identity
      client.cidBuf     = Buffer.from(pkt.cidBuf || Buffer.alloc(16))
      client.uidBuf     = Buffer.alloc(6)
      client.uidStr     = '0000:00000000'
      client.clientType = CLIENT_TYPE_DEVICE
    }

    client.connected = true
    // Remember whether this client uses Pathport's short-vector format (brkHdr=3 → 2-byte vectors)
    // so we can respond in matching format on all subsequent packets to this client.
    client.pathportFormat = !!pkt.pathportFormat

    // Auto-fallback: compute the effective broker vector size for this connection.
    // If a previous REPLY to this IP was rejected, we try the alternate size.
    // Stored on client so keepalive + RPT requests use the same size.
    client.effectiveVecSize = this._getEffectiveVecSize(client)
    if (client.pathportFormat && client.effectiveVecSize !== PATHPORT_OUTGOING_VEC_SIZE) {
      const reason = `primary ${PATHPORT_OUTGOING_VEC_SIZE}-byte was previously rejected`
      console.log(`[Broker] auto-fallback: using ${client.effectiveVecSize}-byte broker vectors for ${client.ip} (${reason})`)
      this._log(`[RDMnet Broker] auto-fallback ${client.effectiveVecSize}-byte vectors for ${client.ip} (${reason})`)
    }

    const typeStr = client.clientType === CLIENT_TYPE_CONTROLLER ? 'Controller' : 'RPT Gateway'
    const fmtStr  = client.pathportFormat ? ` [Pathport format, vec=${client.effectiveVecSize}]` : ''
    this._log(`[RDMnet Broker] BROKER_CONNECT from ${client.ip} — ${typeStr}, UID=${client.uidStr}, CID=${client.cidBuf.toString('hex').toUpperCase()}${fmtStr}`)

    // Send BROKER_CONNECT_REPLY (OK)  ── E1.33 §6.3.4.b
    const reply = buildConnectReply(this.cid, this.uid, client.uidBuf, BROKER_OK, client.pathportFormat, client.effectiveVecSize)
    this._log(`[RDMnet Broker] Sending BROKER_CONNECT_REPLY to ${client.ip} (${reply.length}B, ${client.pathportFormat ? 'E1.33' : 'legacy'} format)`)
    try { socket.write(reply) } catch (_) {}

    // Send BROKER_CONNECTED_CLIENT_LIST  ── E1.33 §6.3.4.c  (MANDATORY)
    // An empty list is valid when no other clients are connected.
    // (The 500ms diagnostic delays from Sessions 15–45 were removed once the
    // handshake was proven against real Pathports — see CLAUDE.md Session 45.)
    const existingPDUs = []
    for (const [existSock, existClient] of this._clients) {
      if (existSock !== socket && existClient.connected && existClient.cidBuf) {
        existingPDUs.push(buildClientEntryPDU(existClient.cidBuf, existClient.uidBuf, existClient.clientType, client.pathportFormat))
      }
    }
    const ccl = buildConnectedClientList(this.cid, existingPDUs, client.pathportFormat, client.effectiveVecSize)
    try { socket.write(ccl) } catch (_) {}
    this._log(`[RDMnet Broker] Sent BROKER_CONNECTED_CLIENT_LIST to ${client.ip} (${existingPDUs.length} existing client(s))`)

    // Send BROKER_CLIENT_ADD to all existing connected clients  ── E1.33 §6.3.4.d
    // Each existing client gets a packet in THEIR preferred format.
    let notified = 0
    for (const [existSock, existClient] of this._clients) {
      if (existSock !== socket && existClient.connected) {
        const newEntryPDU = buildClientEntryPDU(client.cidBuf, client.uidBuf, client.clientType, existClient.pathportFormat)
        const clientAdd   = buildClientAdd(this.cid, newEntryPDU, existClient.pathportFormat, existClient.effectiveVecSize)
        try { existSock.write(clientAdd); notified++ } catch (_) {}
      }
    }
    if (notified > 0) {
      this._log(`[RDMnet Broker] Sent BROKER_CLIENT_ADD to ${notified} existing client(s)`)
    }

    this.emit('gatewayConnected', {
      ip:   client.ip,
      cid:  client.cidBuf.toString('hex'),
      uid:  client.uidStr,
      type: client.clientType === CLIENT_TYPE_CONTROLLER ? 'controller' : 'device',
    })
  }

  // ─── Keepalive ──────────────────────────────────────────────────────────────

  _startKeepalive() {
    this._keepaliveTimer = setInterval(() => {
      for (const [sock, client] of this._clients) {
        if (client.connected) {
          // Use per-client format: Pathport needs Pathport preamble + FL; standard clients get standard
          // effectiveVecSize carries the auto-detected broker vector size (4 or 2)
          const pkt = buildBrokerNull(this.cid, client.pathportFormat, client.effectiveVecSize || null)
          try { sock.write(pkt) } catch (_) {}
        }
      }
    }, KEEPALIVE_MS)
  }

  // ─── Firewall Check (macOS) ─────────────────────────────────────────────────

  _checkFirewall() {
    const fwTool = '/usr/libexec/ApplicationFirewall/socketfilterfw'
    execFile(fwTool, ['--getglobalstate'], (err, stdout) => {
      if (err) {
        this._log('[RDMnet Broker] Could not check macOS firewall status')
        return
      }
      const output = (stdout || '').trim()
      if (output.includes('disabled')) {
        this._log('[RDMnet Broker] macOS firewall: DISABLED (good — port 5569 should be reachable)')
        console.log('[Broker] macOS firewall: DISABLED — port 5569 reachable')
      } else if (output.includes('enabled')) {
        this._log('[RDMnet Broker] ⚠ macOS firewall: ENABLED — port 5569 may be blocked!')
        this._log('[RDMnet Broker]   Pathports may not be able to TCP connect to the broker.')
        this._log('[RDMnet Broker]   Fix: System Settings → Network → Firewall → turn OFF, or add Electron to allowed apps.')
        console.log('[Broker] ⚠ macOS firewall: ENABLED — Pathports may not be able to TCP connect!')
        console.log('[Broker]   Fix: System Settings → Network → Firewall → turn OFF')
        // Also check if Electron specifically is allowed
        execFile(fwTool, ['--listapps'], (err2, stdout2) => {
          if (!err2 && stdout2) {
            const lines = stdout2.split('\n')
            const electronLine = lines.find(l => /electron/i.test(l))
            if (electronLine) {
              this._log(`[RDMnet Broker]   Electron firewall rule: ${electronLine.trim()}`)
              console.log(`[Broker]   Electron firewall rule: ${electronLine.trim()}`)
            } else {
              this._log('[RDMnet Broker]   Electron is NOT in the firewall app list — connections will be blocked!')
              console.log('[Broker]   Electron/node is NOT in firewall allowed list — TCP connections will be dropped!')
            }
          }
        })
      } else {
        this._log(`[RDMnet Broker] macOS firewall status: ${output}`)
        console.log(`[Broker] macOS firewall status: ${output}`)
      }
    })
  }

  // ─── mDNS Advertisement ─────────────────────────────────────────────────────
  //
  // We create ONE UDP socket PER local interface rather than one shared socket
  // with setMulticastInterface() per-send.  The per-send approach is unreliable
  // on macOS — setMulticastInterface() sometimes silently falls back to the
  // default route interface.  With one socket per interface, the multicast
  // outgoing interface is pinned once at socket creation time via
  // setMulticastInterface() and addMembership(), and never has to be changed.

  _startMDNS() {
    this.mDNSIPs = []  // will be populated as sockets bind successfully

    // Collect interface IPs WITH their subnet masks.  The netmask is needed
    // in the query handler to suppress responses from sockets that are not on
    // the same subnet as the querier (fixes multi-NIC conflicting response bug).
    const localNICs = []
    const _seenIPs = new Set()
    for (const [ifName, ifaceList] of Object.entries(os.networkInterfaces())) {
      for (const iface of ifaceList) {
        if (!iface.internal && iface.family === 'IPv4' &&
            !iface.address.startsWith('169.254') &&
            !_seenIPs.has(iface.address)) {
          _seenIPs.add(iface.address)
          localNICs.push({ address: iface.address, netmask: iface.netmask || '255.255.255.0' })
          this._log(`[RDMnet Broker] mDNS NIC: ${ifName} → ${iface.address}/${iface.netmask}`)
          console.log(`[Broker] NIC: ${ifName} → ${iface.address}/${iface.netmask}`)
        }
      }
    }
    if (localNICs.length === 0) localNICs.push({ address: '127.0.0.1', netmask: '255.0.0.0' })

    // We use hand-rolled mDNS exclusively — no dns-sd -R.
    //
    // Why not dns-sd?  Two problems observed in testing:
    //  1. Conflict: dns-sd AND our hand-rolled code both respond to Pathport queries,
    //     producing two simultaneous mDNS responses.  Even with the same hostname,
    //     Pathport firmware seems to discard both on conflict and keeps querying.
    //  2. QU queries: Pathports appear to send Unicast-response (QU) queries.
    //     mDNSResponder may respond unicast (invisible to us), but our response
    //     goes multicast and may be ignored by a QU querier.
    //
    // With hand-rolled mDNS only:
    //  - We are the single authoritative responder for _rdmnet._tcp.local
    //  - We send BOTH unicast (direct to querier) AND multicast on each response
    //  - Only the socket on the same subnet as the querier responds (subnet check)
    //  - No conflicting responses from multiple NICs

    let bound = 0
    for (const { address, netmask } of localNICs) {
      this._createMDNSSocket(address, netmask, () => {
        bound++
        if (bound === localNICs.length) {
          // All sockets bound — announce immediately on preferred NIC only,
          // then at 1s and 5s (RFC 6762 §11.3 probing schedule).
          // _getPreferredSock() picks the non-10.x/non-172.x NIC so there is
          // only ONE SRV record on the network (prevents Pathport picking a
          // random unreachable 10.x IP from multiple SRV records).
          this._announceAll()
          setTimeout(() => this._announceAll(), 1000)
          setTimeout(() => this._announceAll(), 5000)
          // Start periodic re-announce every 30s.
          this._mdnsReannounce = setInterval(() => {
            this._announceAll()
          }, 30000)
          // Attempt 19: dns-sd -P permanently DISABLED.
          //
          // Session 13 tcpdump breakthrough: when dns-sd -P is active, mDNSResponder
          // receives our multicast query responses and generates its OWN combined
          // multicast containing ALL registered services (_smb, _companion-link, _netaudio-cmc,
          // _rdmnet etc.) in a single large packet.  The _rdmnet service appears TWICE
          // in that combined response (once from the subtype PTR RDATA, once from the
          // ADDITIONAL main PTR).  Pathport firmware likely rejects/gets confused by
          // duplicate PTR records or oversized combined mDNS responses.
          //
          // With dns-sd -P disabled, mDNSResponder has NO _rdmnet registration and
          // sends NO response to Pathport queries.  Only our hand-rolled unicast reaches
          // the Pathport — clean, 350B, correct, no duplicates.
          //
          // Do NOT re-enable dns-sd -P without verifying it eliminates the combined
          // mDNS response interference.
          // if (process.platform === 'darwin') this._startDNSSD()  // DISABLED — Attempt 19
        }
      })
    }
  }

  // _startDNSSD() registers the broker via macOS dns-sd -P (proxy registration).
  //
  // WHY re-enable this alongside hand-rolled mDNS?
  //   Both use the SAME per-interface hostname (rdmexplorer-<ip>.local), so
  //   their SRV targets are identical — no conflict, just consistent redundancy.
  //   dns-sd -P registers a real mDNSResponder record, ensuring the Pathport's
  //   standalone A query (if any) goes through mDNSResponder and gets the right IP.
  //
  // WHY per-interface hostname instead of system hostname?
  //   System hostname (e.g. Yoshis-MacBook-Pro.local) is owned by mDNSResponder
  //   which may return the wrong interface IP (en0 10.0.x instead of en11 192.168.1.x).
  //   Our custom hostname has no prior A record → dns-sd -P registers it cleanly.
  //
  // WHY -P instead of -R?
  //   -R uses the system hostname (wrong IP risk).
  //   -P lets us specify both hostname AND IP explicitly → always correct.
  //
  // dns-sd syntax:
  //   dns-sd -P <name> <type>[,subtype...] <domain> <port> <host> <IP> [key=val...]
  _startDNSSD() {
    // Attempt 18: dns-sd -P re-enabled with COMPLETE TXT record (all 7 required E1.33 fields).
    //
    // Previous attempts (12-15) used dns-sd -P with INCOMPLETE TXT (only E133Vers + E133Scope).
    // E1.33 §9.3.3.1 requires CID, UID, Model, Manuf, TxtVers in addition to those two.
    // Pathport firmware validates all fields before initiating TCP — incomplete TXT = silent
    // discard.  TXT was completed in Attempt 17 (hand-rolled) but Pathports still didn't
    // connect.  This attempt delegates main-type mDNS to mDNSResponder (same stack used by
    // ETC's RDMnetBroker, the only known-working macOS broker for Pathway Pathports).
    //
    // Strategy:
    //   • dns-sd -P registers the main _rdmnet._tcp service with full TXT + per-interface hostname
    //   • mDNSResponder handles main-type PTR/SRV/TXT/A responses for _rdmnet._tcp.local
    //   • Hand-rolled code STILL handles _default._sub PTR queries (mDNSResponder gap, Session 8)
    //   • _dnsSDActive = true suppresses hand-rolled sends for non-subtype queries
    //
    // WHY _P not _R?  With -R, mDNSResponder uses the system hostname (e.g. mac.local).
    //   A-record queries for that hostname are answered with ALL interface IPs.  On a
    //   multi-NIC machine (10.0.x + 192.168.1.x), Pathport may get the 10.x IP and try
    //   to connect to an unreachable subnet.  Per-interface hostname forces the correct IP.
    //
    // WHY one NIC only?  Multiple dns-sd -P processes for the SAME service name create
    //   multiple SRV records.  Pathport picks randomly — 2 of 3 may point to 10.x.
    //   One registration = one SRV = deterministic IP.
    const preferred = this._getPreferredSock()
    if (!preferred) {
      this._log('[RDMnet Broker] dns-sd -P: no mDNS sockets available — skipping')
      return
    }
    const { ip } = preferred
    this._log(`[RDMnet Broker] dns-sd -P: selected NIC ${ip} (preferred non-10/172)`)
    console.log(`[Broker] dns-sd -P: using NIC ${ip} only (prevents multiple SRV records)`)

    const hostname = brokerHostnameForIP(ip)
    const cidHex = this.cid.toString('hex')
    const uidHex = this.uid.toString('hex')
    // Full TXT record — all 7 fields required by E1.33 §9.3.3.1.
    // ETC's lwmdns_common.c validates: TxtVers, E133Scope, E133Vers, CID, UID, Model, Manuf.
    // Pathport firmware uses the same E1.33 validation — missing any field = silent discard.
    const args = [
      '-P',
      SERVICE_NAME,
      '_rdmnet._tcp,_default',
      'local',
      String(RDMNET_PORT),
      hostname,
      ip,
      'TxtVers=1',
      'E133Scope=default',
      'E133Vers=1',
      `CID=${cidHex}`,
      `UID=${uidHex}`,
      'Model=RDM-Explorer',
      'Manuf=OpenSource',
    ]
    this._log(`[RDMnet Broker] Starting dns-sd -P for ${ip}: dns-sd ${args.join(' ')}`)
    console.log(`[Broker] dns-sd -P on ${ip} → ${hostname}`)
    try {
      const child = spawn('dns-sd', args, { detached: false })
      child.stdout.on('data', d => {
        const line = d.toString().trim()
        if (line) {
          this._log(`[RDMnet Broker] dns-sd[${ip}]: ${line}`)
          console.log(`[Broker] dns-sd[${ip}]: ${line}`)
        }
      })
      child.stderr.on('data', d => {
        const line = d.toString().trim()
        if (line) this._log(`[RDMnet Broker] dns-sd[${ip}] err: ${line}`)
      })
      child.on('exit', (code) => {
        this._log(`[RDMnet Broker] dns-sd[${ip}] exited (code=${code})`)
        if (this._dnsSdProcesses) {
          this._dnsSdProcesses = this._dnsSdProcesses.filter(e => e.child !== child)
        }
      })
      this._dnsSdProcesses.push({ child, ip })
      // dns-sd is now the authoritative mDNS responder for main-type queries.
      // Suppress hand-rolled sends for non-subtype queries so there is only
      // ONE responder per query type (prevents conflicting simultaneous responses).
      this._dnsSDActive = true
      this._log(`[RDMnet Broker] dns-sd active — hand-rolled sends suppressed for non-subtype queries`)
      console.log(`[Broker] dns-sd -P active — hand-rolled mDNS suppressed (subtype PTR gap still filled)`)
    } catch (e) {
      this._log(`[RDMnet Broker] dns-sd spawn failed on ${ip}: ${e.message}`)
    }
  }

  _createMDNSSocket(ip, netmask, onComplete) {
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true })

    sock.on('error', (err) => {
      this._log(`[RDMnet Broker] mDNS socket error on ${ip}: ${err.message}`)
      // Remove from active list
      this._mdnsSocks = this._mdnsSocks.filter(e => e.sock !== sock)
      this.mDNSIPs    = this._mdnsSocks.map(e => e.ip)
      if (this.mDNSIPs.length === 0) this.mDNSError = err.message
      try { sock.close() } catch (_) {}
      if (onComplete) onComplete()
    })

    sock.bind({ port: MDNS_PORT, address: '0.0.0.0' }, () => {
      // Guard: if the broker was stopped while the async bind was in progress,
      // discard this orphaned socket immediately.  Without this, unit-test brokers
      // that call start() then stop() quickly leave zombie sockets that continue
      // receiving mDNS queries after the broker is "stopped".
      if (!this.running) {
        try { sock.close() } catch (_) {}
        if (onComplete) onComplete()
        return
      }
      // Pin this socket to a single interface for sending AND receiving.
      try { sock.addMembership(MDNS_ADDR, ip) } catch (e) {
        this._log(`[RDMnet Broker] mDNS addMembership failed on ${ip}: ${e.message}`)
      }
      try { sock.setMulticastInterface(ip) } catch (e) {
        this._log(`[RDMnet Broker] mDNS setMulticastInterface failed on ${ip}: ${e.message}`)
      }
      try { sock.setMulticastTTL(255) }       catch (_) {}
      try { sock.setMulticastLoopback(false) } catch (_) {}

      this._mdnsSocks.push({ ip, netmask, sock })
      this.mDNSIPs.push(ip)
      const sysHost = brokerHostnameForIP(ip)
      const _testPkt = buildSubtypePTRResponse(ip, this.cid, this.uid)
      const _pktSize = _testPkt.length
      this._log(`[RDMnet Broker] mDNS socket ready on ${ip}/${netmask} — hand-rolled mDNS, SRV→${sysHost}:${RDMNET_PORT}, pkt=${_pktSize}B (ptr-safe)`)
      console.log(`[Broker] mDNS ready on ${ip} — pkt=${_pktSize}B (ptr-safe), SRV→${sysHost}:${RDMNET_PORT}`)

      // Handle incoming mDNS messages: log queries AND responses for _rdmnet._tcp
      sock.on('message', (msg, rinfo) => {
        try {
          if (isMDNSQueryForRDMnet(msg)) {
            const querierIP = rinfo.address
            const queryNames = extractQueryNames(msg)
            const queryDetail = queryNames.length > 0 ? ` [${queryNames.join(', ')}]` : ''

            // Check if this is a subtype browse for _default._sub._rdmnet._tcp.local.
            // mDNSResponder may not respond to subtype PTR queries correctly on all
            // interfaces, so we ALWAYS send our own hand-rolled response for this
            // specific query — even when dns-sd is active.  The SRV target uses the
            // system hostname (same as dns-sd) so there is no conflict.
            const isSubtypeQuery = queryNames.some(n => n.includes('_default._sub'))

            // Only respond from the socket whose subnet matches the querier.
            // With reuseAddr + 0.0.0.0 binding, macOS delivers each incoming
            // multicast to ALL sockets — without this guard, every query triggers
            // N conflicting responses (one per NIC), confusing Pathport firmware.
            const onSameSubnet = isSameSubnet(ip, querierIP, netmask)

            // When dns-sd -P is active, mDNSResponder is the SOLE responder — including
            // for _default._sub subtype queries.  Verified in Session 45 (`dns-sd -B
            // _rdmnet._tcp,_default` resolves fine): the -P registration with the
            // ",_default" subtype makes mDNSResponder answer subtype browses itself.
            // Responding from here as well recreates the Session 7 dual-responder
            // conflict that stops Pathport firmware from ever TCP-connecting.
            const shouldRespond = !this._dnsSDActive

            if (querierIP !== ip && !querierIP.startsWith('127.') && onSameSubnet && shouldRespond) {
              const kind = isSubtypeQuery ? 'SUBTYPE' : 'GENERAL'
              // QU bit is in the QCLASS field of the first question, which is after
              // the QNAME.  For `_default._sub._rdmnet._tcp.local` the QNAME is 34B,
              // so QCLASS starts at offset 12+34 = 46.  Bit 15 of QCLASS = QU bit.
              const quBit = msg.length >= 50 ? !!(msg.readUInt16BE(48) & 0x8000) : false
              const PATHPORT_IPS2 = ['192.168.1.39','192.168.1.40','192.168.1.41','192.168.1.42']
              const _queryT = Date.now()

              {
              // Response dedup: one response per querier per 500ms, shared across ALL
              // broker instances (module-level Map).  During tests multiple broker
              // instances run concurrently; per-instance dedup is insufficient.
              const _now = Date.now()
              const _lastSent = _globalMDNSResponseDedup.get(querierIP) || 0
              if (_now - _lastSent < 500) {
                // Already responded to this querier within 500ms — skip duplicate
              } else {
              _globalMDNSResponseDedup.set(querierIP, _now)

              this._log(`[RDMnet Broker] mDNS ${kind} query from ${querierIP} on ${ip}${queryDetail} — sending unicast-only response`)
              if (PATHPORT_IPS2.includes(querierIP) || isSubtypeQuery) {
                console.log(`[Broker] t=${_queryT%100000} mDNS ${kind} query from ${querierIP} on ${ip} QU=${quBit} qdCount=${msg.readUInt16BE(4)} len=${msg.length} — responding`)
              }
              // Capture the source port NOW (before the setTimeout fires)
              const _srcPort = rinfo.port
              setTimeout(() => {
                try {
                  const resp = buildSubtypePTRResponse(ip, this.cid, this.uid)
                  const PATHPORT_IPS3 = ['192.168.1.39','192.168.1.40','192.168.1.41','192.168.1.42']
                  if (PATHPORT_IPS3.includes(querierIP)) {
                    console.log(`[Broker] t=${Date.now()%100000} (+${Date.now()-_queryT}ms) sending ${resp.length}B (ptr-safe) to ${querierIP} (unicast+multicast) from ${ip} QU=${quBit}`)
                  }
                  // Attempt 20: UNICAST + MULTICAST.
                  //
                  // Attempt 19 (unicast-only) eliminated mDNSResponder interference but
                  // Pathports still didn't connect.  ETC's reference implementation uses
                  // DNSServiceRegister() (Bonjour API), which sends responses via mDNSResponder
                  // as MULTICAST.  Pathport firmware may only process multicast mDNS responses
                  // and silently ignore unicast-only responses.
                  //
                  // Now that ETC's broker is killed and dns-sd is fully disabled, mDNSResponder
                  // has ZERO _rdmnet registrations.  When it receives our multicast it has nothing
                  // to combine/re-broadcast — so the interference problem from earlier attempts
                  // no longer applies.
                  //
                  // Send BOTH unicast (RFC 6762 §6.7 for QU queries) AND multicast (required
                  // by Pathport firmware which only processes multicast mDNS responses).
                  const sendUnicast = (port) => {
                    sock.send(resp, 0, resp.length, port, querierIP, (err) => {
                      if (err) {
                        console.log(`[Broker] !! unicast FAILED to ${querierIP}:${port}: ${err.message}`)
                        this._log(`[RDMnet Broker] unicast error to ${querierIP}:${port}: ${err.message}`)
                        this._maybeActivateDNSSDFallback(err)
                      } else {
                        console.log(`[Broker] unicast ${resp.length}B → ${querierIP}:${port} OK`)
                        this._log(`[RDMnet Broker] unicast sent to ${querierIP}:${port} from ${ip}`)
                      }
                    })
                  }
                  sendUnicast(_srcPort)
                  if (_srcPort !== MDNS_PORT) sendUnicast(MDNS_PORT)
                  // Also send multicast so Pathport firmware receives it via the expected path.
                  sock.send(resp, 0, resp.length, MDNS_PORT, MDNS_ADDR, (err) => {
                    if (err) {
                      this._log(`[RDMnet Broker] multicast response error: ${err.message}`)
                    } else {
                      console.log(`[Broker] multicast ${resp.length}B → ${MDNS_ADDR} OK from ${ip}`)
                      this._log(`[RDMnet Broker] multicast response sent from ${ip}`)
                    }
                  })
                } catch (e) {
                  this._log(`[RDMnet Broker] response build error: ${e.message}`)
                }
              }, 0)
              } // end else (dedup check)
              }
            }
            // Track queriers to detect devices that query but never TCP connect.
            // Only count from the socket that will respond (same-subnet socket)
            // to avoid inflating the count when multiple sockets see the same query.
            if (!querierIP.startsWith('127.') && querierIP !== ip && onSameSubnet) {
              const q = this._mdnsQueriers.get(querierIP) || { firstSeen: Date.now(), queryCount: 0, warned: false }
              q.queryCount++
              q.lastSeen = Date.now()
              this._mdnsQueriers.set(querierIP, q)
              // After first query from a device with no TCP connection, wait 3s then warn.
              // The 3s window gives the device time to complete the TCP handshake before we
              // flag it as "not connecting".  Fires after each query (but only once per device).
              if (q.queryCount === 1 && !q.warned) {
                q.warned = true
                setTimeout(() => {
                  const isConnected = [...this._clients.values()].some(c => c.connected && c.ip.includes(querierIP))
                  if (!isConnected) {
                    console.log(`[Broker] ⚠ ${querierIP} queried mDNS but has NOT TCP connected (3s after response)`)
                    this._log(`[RDMnet Broker] ⚠ ${querierIP} has sent ${q.queryCount} mDNS quer${q.queryCount === 1 ? 'y' : 'ies'} but has NOT TCP connected.`)
                  }
                }, 3000)
              }
            }
          } else {
            // Log all non-rdmnet traffic from the 4 known Pathport IPs — full hex
            const PATHPORT_IPS = ['192.168.1.39','192.168.1.40','192.168.1.41','192.168.1.42']
            if (PATHPORT_IPS.includes(rinfo.address)) {
              const isResp = !!(msg.readUInt16BE(2) & 0x8000)
              const names = extractQueryNames(msg)
              console.log(`[Broker] non-rdmnet pkt from ${rinfo.address} on ${ip}: ${isResp ? 'resp' : 'query'} names=[${names.join(',')}] len=${msg.length}`)
              console.log(`[Broker]   hex: ${msg.toString('hex')}`)
            }

            // Check if this is an A-record query for OUR per-interface hostname.
            // When dns-sd -P is active, mDNSResponder owns the A record and responds.
            // When hand-rolled only, we respond ourselves.
            const ourHostname = brokerHostnameForIP(ip)
            const aQuery = isAQueryForHostname(msg, ourHostname)
            if (aQuery && rinfo.address !== ip && !rinfo.address.startsWith('127.')
                && isSameSubnet(ip, rinfo.address, netmask)) {
              console.log(`[Broker] A-record query for ${ourHostname} from ${rinfo.address} — responding`)
              this._log(`[RDMnet Broker] A-record query for ${ourHostname} from ${rinfo.address} — sending A response ${ip}`)
              const aResp = buildAResponse(ourHostname, ip)
              // Unicast back to querier (handles QU queries)
              // Unicast only — no multicast (same reason: prevents mDNSResponder adoption)
              sock.send(aResp, 0, aResp.length, MDNS_PORT, rinfo.address, (err) => {
                if (err) this._log(`[RDMnet Broker] A unicast error to ${rinfo.address}: ${err.message}`)
                else console.log(`[Broker] A-record unicast ${aResp.length}B → ${rinfo.address} OK`)
              })
            }

            // NOTE: general hostname-query logging removed (Session 45) — chatty
            // office subnets (_companion-link, _airplay, …) generated thousands of
            // log lines per scan and drowned the UI progress feed.
            // Check if this is an mDNS RESPONSE for _rdmnet (from dns-sd or another broker).
            // Log the advertised SRV target and A record IPs so we can verify Pathports
            // are seeing the correct IP address for this broker.
            const resp = parseMDNSResponseForRDMnet(msg)
            if (resp) {
              const parts = []
              if (resp.ptrTargets.length > 0) parts.push(`PTR→${resp.ptrTargets.join(',')}`)
              if (resp.srvTarget)              parts.push(`SRV→${resp.srvTarget}:${resp.srvPort}`)
              if (resp.aRecords.length > 0)    parts.push(`A→${resp.aRecords.join(',')}`)
              this._log(`[RDMnet Broker] mDNS response on ${ip} from ${rinfo.address}: ${parts.join(' ')}`)
              // Interference check: if we receive an mDNS response from OUR OWN IP
              // that contains our service, mDNSResponder is re-advertising it and
              // competing with us.  Log loudly so we can detect this.
              if (rinfo.address === ip && parts.length > 0) {
                console.log(`[Broker] !! mDNSResponder? response from OUR OWN IP ${ip} — ${parts.join(' ')} — INTERFERENCE DETECTED`)
                this._log(`[RDMnet Broker] !! mDNSResponder interference: response from own IP ${ip}: ${parts.join(' ')}`)
              }
            }
          }
        } catch (_) {}
      })

      // Per-socket startup announcement moved to "all sockets bound" callback
      // (_startMDNS) so we can use _getPreferredSock() — prevent multi-SRV problem.
      if (onComplete) onComplete()
    })
  }

  // Send an mDNS announcement (multicast + unicast to known queriers) using the
  // preferred NIC socket.  setMulticastLoopback(false) prevents mDNSResponder
  // from receiving our multicast and creating stale registrations.  Pathports
  // on the wire receive the multicast normally.  Unicast copies are sent to
  // any previously-seen querier IPs as an additional delivery path.
  _announceOn(sock, ip) {
    try {
      const announcement = buildMDNSAnnouncement(ip, this.cid, this.uid)
      // Attempt 20: multicast announce (same path ETC's DNSServiceRegister uses).
      // With dns-sd disabled and ETC's broker killed, mDNSResponder has zero _rdmnet
      // registrations — it will not re-broadcast our multicast.
      sock.send(announcement, 0, announcement.length, MDNS_PORT, MDNS_ADDR, (err) => {
        if (err) {
          this._log(`[RDMnet Broker] announce multicast error from ${ip}: ${err.message}`)
          this._maybeActivateDNSSDFallback(err)
        }
        else this._log(`[RDMnet Broker] multicast announce sent from ${ip}`)
      })
      // Also unicast to any previously-seen queriers as belt-and-suspenders.
      const queriers = [...this._mdnsQueriers.keys()].filter(
        qip => !qip.startsWith('127.') && qip !== ip
      )
      for (const qip of queriers) {
        sock.send(announcement, 0, announcement.length, MDNS_PORT, qip, (err) => {
          if (err) this._log(`[RDMnet Broker] announce unicast error to ${qip}: ${err.message}`)
          else this._log(`[RDMnet Broker] unicast announce sent to ${qip} from ${ip}`)
        })
      }
    } catch (err) {
      this._log(`[RDMnet Broker] mDNS announce exception on ${ip}: ${err.message}`)
    }
  }

  /**
   * macOS Local Network privacy fallback.
   *
   * On macOS 15+ each app needs the "Local Network" permission (System Settings →
   * Privacy & Security → Local Network).  When it is denied, every UDP send to a
   * local-subnet or multicast address fails with EHOSTUNREACH and inbound multicast
   * is silently filtered — the broker becomes deaf and mute on mDNS while TCP on
   * established connections still works.
   *
   * mDNSResponder (Apple's system mDNS daemon) is exempt, so when we detect the
   * denial we register the broker through it via `dns-sd -P` instead.  The
   * historical dual-responder interference (Session 13) cannot occur here because
   * our own multicast sends are blocked — mDNSResponder is the sole responder.
   */
  _maybeActivateDNSSDFallback(err) {
    if (!err || (err.code !== 'EHOSTUNREACH' && err.code !== 'EACCES')) return
    if (process.platform !== 'darwin') return
    if (this._dnsSDActive || this._dnsSdFallbackTried) return
    this._dnsSdFallbackTried = true
    this._log(`[RDMnet Broker] ⚠ direct mDNS send blocked (${err.code}) — macOS Local Network permission is likely DENIED for this app`)
    this._log('[RDMnet Broker]   Falling back to mDNSResponder registration (dns-sd -P).')
    this._log('[RDMnet Broker]   For full functionality (Art-Net/sACN discovery too) allow this app in:')
    this._log('[RDMnet Broker]   System Settings → Privacy & Security → Local Network')
    console.log(`[Broker] ⚠ mDNS send blocked (${err.code}) — activating dns-sd fallback (macOS Local Network permission denied?)`)
    this._startDNSSD()
  }

  // Return the single preferred mDNS socket for proactive announcements.
  // We only announce on ONE NIC to prevent multiple SRV records for the same
  // service instance name (one per NIC), which would cause clients to pick a
  // random SRV — 2-of-3 pointing to unreachable 10.x/172.x IPs.
  //
  // All sockets remain active for RECEIVING queries; only the preferred one
  // sends unsolicited announcements.  Query RESPONSES always come from the
  // socket on the same subnet as the querier (isSameSubnet check), so devices
  // on any subnet still get a correct unicast response when they ask.
  _getPreferredSock() {
    const isPreferred = ip => !ip.startsWith('10.') && !ip.startsWith('172.')
    return this._mdnsSocks.find(({ ip }) => isPreferred(ip)) || this._mdnsSocks[0]
  }

  _announceAll() {
    const preferred = this._getPreferredSock()
    if (preferred) this._announceOn(preferred.sock, preferred.ip)
  }

  _getAllLocalIPs() {
    // Return all non-loopback, non-link-local IPv4 addresses (one per NIC).
    const ips = []
    for (const ifaces of Object.values(os.networkInterfaces())) {
      for (const iface of ifaces) {
        if (!iface.internal && iface.family === 'IPv4' &&
            !iface.address.startsWith('169.254')) {
          ips.push(iface.address)
        }
      }
    }
    return ips.length > 0 ? ips : ['127.0.0.1']
  }

  // Keep _getLocalIP() for any callers that still need a single IP fallback
  _getLocalIP() {
    const ips = this._getAllLocalIPs()
    return ips[0]
  }
}

module.exports = RDMnetBroker
module.exports.brokerHostnameForIP = brokerHostnameForIP
