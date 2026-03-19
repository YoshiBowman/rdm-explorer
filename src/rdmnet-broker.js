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

const RDMNET_PORT    = 5569
const MDNS_ADDR      = '224.0.0.251'
const MDNS_PORT      = 5353
const KEEPALIVE_MS   = 15000   // Send BROKER_NULL every 15 s
const MDNS_TTL       = 4500    // mDNS record TTL (seconds)
const SERVICE_NAME   = 'RDM Explorer'

// Root Layer PDU vectors (E1.33 Table A-3)
const VECTOR_ROOT_BROKER  = 0x00000009
const VECTOR_ROOT_RPT     = 0x00000005

// Broker PDU vectors (E1.33 Table A-8)
const VECTOR_BROKER_CONNECT                 = 0x00000001
const VECTOR_BROKER_CONNECT_REPLY           = 0x00000002
const VECTOR_BROKER_NULL                    = 0x00000005
const VECTOR_BROKER_DISCONNECT              = 0x00000004
const VECTOR_BROKER_CLIENT_ENTRY_RPT        = 0x00000001
const VECTOR_BROKER_CONNECTED_CLIENT_LIST   = 0x00000006
const VECTOR_BROKER_CLIENT_ADD              = 0x00000007

// RPT PDU vectors (E1.33 Table A-11)
const VECTOR_RPT_REQUEST      = 0x00000001
const VECTOR_RPT_STATUS       = 0x00000002
const VECTOR_RPT_NOTIFICATION = 0x00000003

// RDM Command PDU inner vectors
const VECTOR_REQUEST_RDM_CMD      = 0x00000001
const VECTOR_NOTIFICATION_RDM_CMD = 0x00000001

// Broker Connect Reply codes
const BROKER_OK             = 0x0000
const BROKER_CAPACITY_FULL  = 0x0003
const BROKER_WRONG_SCOPE    = 0x0004

// E1.33 protocol version
const E133_VERSION = 0x0001

// Client types in Client Entry PDU
const CLIENT_TYPE_CONTROLLER = 0x01
const CLIENT_TYPE_DEVICE     = 0x02  // RPT Gateway / Fixture

// ACN Packet Identifier (E1.17) — first 12 bytes after preamble
const ACN_PID = Buffer.from('4153432d45312e313700000000000000', 'hex').slice(0, 12)

// ─── PDU Helpers (self-contained copies; intentionally not importing rdmnet.js
//     to keep broker.js usable standalone) ──────────────────────────────────────

function flagsAndLength(bodyLen) {
  const total = bodyLen + 2
  return [0x70 | ((total >> 8) & 0x0F), total & 0xFF]
}

function buildPDU(vector, header, data) {
  const body = Buffer.alloc(4 + header.length + data.length)
  body.writeUInt32BE(vector, 0)
  header.copy(body, 4)
  data.copy(body, 4 + header.length)
  const [hi, lo] = flagsAndLength(body.length)
  const out = Buffer.alloc(2 + body.length)
  out[0] = hi; out[1] = lo
  body.copy(out, 2)
  return out
}

function wrap(pdu) {
  // Prepend the 16-byte ACN preamble
  const pre = Buffer.alloc(16)
  pre.writeUInt16BE(0x0010, 0)
  pre.writeUInt16BE(0x0000, 2)
  ACN_PID.copy(pre, 4)
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
function buildConnectReply(brokerCID, brokerUID, clientUID, code = BROKER_OK) {
  const data = Buffer.alloc(16)
  data.writeUInt16BE(code, 0)
  data.writeUInt16BE(E133_VERSION, 2)
  brokerUID.copy(data, 4)
  clientUID.copy(data, 10)
  const brokerPDU = buildPDU(VECTOR_BROKER_CONNECT_REPLY, Buffer.alloc(0), data)
  return wrap(buildPDU(VECTOR_ROOT_BROKER, brokerCID, brokerPDU))
}

/**
 * Build a BROKER_NULL keepalive packet.
 * Sent periodically to keep TCP connections alive.
 */
function buildBrokerNull(brokerCID) {
  const brokerPDU = buildPDU(VECTOR_BROKER_NULL, Buffer.alloc(0), Buffer.alloc(0))
  return wrap(buildPDU(VECTOR_ROOT_BROKER, brokerCID, brokerPDU))
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
function buildRPTRequest(brokerCID, ctrlUID, destUID, destEndpoint, seqNum, rdmPacket) {
  const hdr = Buffer.alloc(20)
  ctrlUID.copy(hdr, 0)
  hdr.writeUInt16BE(0, 6)           // src endpoint: controller
  destUID.copy(hdr, 8)
  hdr.writeUInt16BE(destEndpoint, 14)
  hdr.writeUInt32BE(seqNum >>> 0, 16)
  const rdmCmdPDU = buildPDU(VECTOR_REQUEST_RDM_CMD, Buffer.alloc(0), rdmPacket)
  const rptPDU    = buildPDU(VECTOR_RPT_REQUEST, hdr, rdmCmdPDU)
  return wrap(buildPDU(VECTOR_ROOT_RPT, brokerCID, rptPDU))
}

// ─── TCP Stream Parser ────────────────────────────────────────────────────────

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

    // Locate ACN PID
    if (!buf.slice(offset + 4, offset + 16).equals(ACN_PID)) { offset++; continue }

    if (offset + 22 > buf.length) break
    const rootLen = ((buf[offset + 16] & 0x0F) << 8) | buf[offset + 17]
    const total   = 16 + rootLen
    if (total < 22 || offset + total > buf.length) { offset++; continue }

    const pkt = _parseACNFrame(buf.slice(offset, offset + total))
    if (pkt) packets.push(pkt)
    offset += total
  }

  return { packets, remainder: buf.slice(offset) }
}

function _parseACNFrame(buf) {
  try {
    // Root layer: offset 16+
    const rootLen  = ((buf[16] & 0x0F) << 8) | buf[17]
    const rootVec  = buf.readUInt32BE(18)
    const rootCID  = buf.slice(22, 38)
    const child    = buf.slice(38, 16 + rootLen)

    const result = {
      rootVector: rootVec,
      cid: rootCID.toString('hex'),
      cidBuf: rootCID,
    }

    // ── Broker layer ────────────────────────────────────────────────────────
    if (rootVec === VECTOR_ROOT_BROKER && child.length >= 6) {
      const brkLen  = ((child[0] & 0x0F) << 8) | child[1]
      const brkVec  = child.readUInt32BE(2)
      const brkData = child.slice(6, brkLen)

      if (brkVec === VECTOR_BROKER_CONNECT) {
        result.type = 'broker_connect'
        // Header: Scope(63) + E133Ver(2) + SearchDomain(231) + Flags(1) = 297 bytes
        if (brkData.length >= 297) {
          result.scope   = brkData.slice(0, 63).toString('utf8').replace(/\0/g, '').trim()
          result.flags   = brkData[296]
        }
        // Client Entry PDU begins at offset 297
        if (brkData.length > 297) {
          const entryBuf = brkData.slice(297)
          if (entryBuf.length >= 6) {
            const eLen  = ((entryBuf[0] & 0x0F) << 8) | entryBuf[1]
            const eData = entryBuf.slice(6, eLen)  // skip flags+length(2)+vector(4)
            if (eData.length >= 23) {
              result.clientCIDBuf  = eData.slice(0, 16)
              result.clientCID     = result.clientCIDBuf.toString('hex')
              result.clientUIDBuf  = eData.slice(16, 22)
              result.clientUID     = result.clientUIDBuf.toString('hex').toUpperCase()
              result.clientType    = eData[22]   // 0x01=Controller 0x02=Device
              result.uidStr        = uidStr(result.clientUIDBuf)
            }
          }
        }
      } else if (brkVec === VECTOR_BROKER_NULL) {
        result.type = 'broker_null'
      } else if (brkVec === VECTOR_BROKER_DISCONNECT) {
        result.type = 'broker_disconnect'
      } else {
        result.type = `broker_unknown_${brkVec}`
      }
    }

    // ── RPT layer ───────────────────────────────────────────────────────────
    if (rootVec === VECTOR_ROOT_RPT && child.length >= 6) {
      const rptLen  = ((child[0] & 0x0F) << 8) | child[1]
      const rptVec  = child.readUInt32BE(2)
      const rptBody = child.slice(6, rptLen)

      if (rptBody.length >= 20) {
        result.srcUID      = rptBody.slice(0, 6)
        result.srcEndpoint = rptBody.readUInt16BE(6)
        result.destUID     = rptBody.slice(8, 14)
        result.destEndpoint= rptBody.readUInt16BE(14)
        result.seqNum      = rptBody.readUInt32BE(16)
        const payload      = rptBody.slice(20)

        if (rptVec === VECTOR_RPT_NOTIFICATION && payload.length >= 6) {
          result.type = 'rpt_notification'
          // Inner RDM Command PDU: flags+length(2) + vector(4) + data
          const innerLen = ((payload[0] & 0x0F) << 8) | payload[1]
          result.rdmData = payload.slice(6, innerLen)
        } else if (rptVec === VECTOR_RPT_STATUS) {
          result.type = 'rpt_status'
          if (payload.length >= 6) result.statusCode = payload.readUInt32BE(2)
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
function buildMDNSAnnouncement(localIP) {
  return buildSubtypePTRResponse(localIP)
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
 * The response includes:
 *   Answer section:  PTR  _default._sub._rdmnet._tcp.local → RDM Explorer._rdmnet._tcp.local
 *                    PTR  _rdmnet._tcp.local → RDM Explorer._rdmnet._tcp.local
 *   Additional:      SRV  RDM Explorer._rdmnet._tcp.local → rdmexplorer-<ip>.local:5569
 *                    TXT  RDM Explorer._rdmnet._tcp.local → E133Vers=1, E133Scope=default
 *                    A    rdmexplorer-<ip>.local → <localIP>
 */
function buildSubtypePTRResponse(localIP) {
  // Use per-interface hostname — immune to mDNSResponder interference
  const sysHost  = brokerHostnameForIP(localIP)
  const fullSvc  = `${SERVICE_NAME}._rdmnet._tcp.local`
  const svcType  = `_rdmnet._tcp.local`
  const subType  = `_default._sub._rdmnet._tcp.local`

  const subName  = encodeDNSName(subType)
  const ptrName  = encodeDNSName(svcType)
  const svcName  = encodeDNSName(fullSvc)
  const hostName = encodeDNSName(sysHost)

  // PTR rdata → full service instance name
  const ptrRdata = svcName

  // SRV rdata: priority(2) + weight(2) + port(2) + target
  const srvRdata = Buffer.alloc(6 + hostName.length)
  srvRdata.writeUInt16BE(0, 0)   // priority
  srvRdata.writeUInt16BE(0, 2)   // weight
  srvRdata.writeUInt16BE(RDMNET_PORT, 4)
  hostName.copy(srvRdata, 6)

  // TXT rdata: length-prefixed strings per DNS spec
  const txtStrings = ['E133Vers=1', 'E133Scope=default']
  const txtParts = txtStrings.map(s => {
    const b = Buffer.alloc(1 + s.length)
    b[0] = s.length
    Buffer.from(s, 'ascii').copy(b, 1)
    return b
  })
  const txtRdata = Buffer.concat(txtParts)

  // A rdata: IPv4 address bytes
  const aRdata = Buffer.from(localIP.split('.').map(Number))

  // Build individual records — PTR is shared (no cache-flush), others are unique
  const subPtrRec = buildDNSRecord(subName,  12, MDNS_TTL, ptrRdata, false) // PTR (subtype) — shared
  const ptrRec    = buildDNSRecord(ptrName,  12, MDNS_TTL, ptrRdata, false) // PTR (main type) — shared
  const srvRec    = buildDNSRecord(svcName,  33, MDNS_TTL, srvRdata, true)  // SRV — unique
  const txtRec    = buildDNSRecord(svcName,  16, MDNS_TTL, txtRdata, true)  // TXT — unique
  const aRec      = buildDNSRecord(hostName,  1, MDNS_TTL, aRdata, true)    // A — unique

  // DNS response header: QR=1 AA=1, 2 answers (subtype PTR + main PTR), 3 additional (SRV+TXT+A)
  const hdr = Buffer.alloc(12)
  hdr.writeUInt16BE(0,      0)   // ID = 0 (mDNS)
  hdr.writeUInt16BE(0x8400, 2)   // Flags: response + authoritative
  hdr.writeUInt16BE(0,      4)   // Questions = 0
  hdr.writeUInt16BE(2,      6)   // Answer RRs = 2 (subtype PTR + main PTR)
  hdr.writeUInt16BE(0,      8)   // Authority RRs = 0
  hdr.writeUInt16BE(3,     10)   // Additional RRs = 3 (SRV, TXT, A)

  return Buffer.concat([hdr, subPtrRec, ptrRec, srvRec, txtRec, aRec])
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
    this.cid      = makeCID()
    this.uid      = makeUID()
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
          ip:     sock.remoteAddress,
        })
      }
    }
    return gateways
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
      // Find the socket for this gateway
      let targetSock = null
      for (const [sock, client] of this._clients) {
        if (client.connected && client.cidBuf &&
            client.cidBuf.equals(gatewayCIDBuf)) {
          targetSock = sock
          break
        }
      }
      if (!targetSock) return resolve(null)

      const seqNum = (this._seq++) >>> 0
      const pkt    = buildRPTRequest(this.cid, this.uid, destUID, destEndpoint, seqNum, rdmPacket)

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
      client.buf = Buffer.concat([client.buf, chunk])
      const { packets, remainder } = parseTCPStream(client.buf)
      client.buf = remainder
      for (const pkt of packets) this._handlePacket(socket, client, pkt)
    })

    socket.on('close', () => {
      const c = this._clients.get(socket)
      if (c && c.cidBuf) {
        this._log(`[RDMnet Broker] Client disconnected: ${c.ip} UID=${c.uidStr}`)
        this.emit('gatewayDisconnected', { ip: c.ip, cid: c.cidBuf.toString('hex'), uid: c.uidStr })
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
        // Keepalive from client — echo one back
        try { socket.write(buildBrokerNull(this.cid)) } catch (_) {}
        break

      case 'broker_disconnect':
        try { socket.destroy() } catch (_) {}
        break

      case 'rpt_notification': {
        // RDM response coming back from the gateway
        if (pkt.rdmData && pkt.seqNum !== undefined) {
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
        // Gateway reporting an RDM-level error (timeout, NACK, etc.)
        if (pkt.seqNum !== undefined) {
          const pending = this._pending.get(pkt.seqNum)
          if (pending) {
            clearTimeout(pending.timer)
            this._pending.delete(pkt.seqNum)
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

  _handleBrokerConnect(socket, client, pkt) {
    // Record the gateway's identity from the Client Entry PDU
    if (pkt.clientCIDBuf) {
      client.cidBuf     = pkt.clientCIDBuf
      client.uidBuf     = pkt.clientUIDBuf || Buffer.alloc(6)
      client.uidStr     = pkt.uidStr       || '0000:00000000'
      client.clientType = pkt.clientType   || CLIENT_TYPE_DEVICE
    } else {
      // Fallback: use root-layer CID as identity
      client.cidBuf     = Buffer.from(pkt.cidBuf || Buffer.alloc(16))
      client.uidBuf     = Buffer.alloc(6)
      client.uidStr     = '0000:00000000'
      client.clientType = CLIENT_TYPE_DEVICE
    }

    client.connected = true

    const typeStr = client.clientType === CLIENT_TYPE_CONTROLLER ? 'Controller' : 'RPT Gateway'
    this._log(`[RDMnet Broker] BROKER_CONNECT from ${client.ip} — ${typeStr}, UID=${client.uidStr}, CID=${client.cidBuf.toString('hex').toUpperCase()}`)

    // Send BROKER_CONNECT_REPLY (OK)
    const reply = buildConnectReply(this.cid, this.uid, client.uidBuf, BROKER_OK)
    try { socket.write(reply) } catch (_) {}

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
      const pkt = buildBrokerNull(this.cid)
      for (const [sock, client] of this._clients) {
        if (client.connected) {
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
      } else if (output.includes('enabled')) {
        this._log('[RDMnet Broker] ⚠ macOS firewall: ENABLED — port 5569 may be blocked!')
        this._log('[RDMnet Broker]   Pathports may not be able to TCP connect to the broker.')
        this._log('[RDMnet Broker]   Fix: System Settings → Network → Firewall → turn OFF, or add Electron to allowed apps.')
        // Also check if Electron specifically is allowed
        execFile(fwTool, ['--listapps'], (err2, stdout2) => {
          if (!err2 && stdout2) {
            const lines = stdout2.split('\n')
            const electronLine = lines.find(l => /electron/i.test(l))
            if (electronLine) {
              this._log(`[RDMnet Broker]   Electron firewall rule: ${electronLine.trim()}`)
            } else {
              this._log('[RDMnet Broker]   Electron is NOT in the firewall app list — connections will be blocked!')
            }
          }
        })
      } else {
        this._log(`[RDMnet Broker] macOS firewall status: ${output}`)
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
    const localIPs = this._getAllLocalIPs()
    this.mDNSIPs = []  // will be populated as sockets bind successfully

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
    //  - We use the system hostname (os.hostname()) so A-record follow-up queries
    //    are handled by mDNSResponder natively — it always knows its own hostname
    //  - No conflicting responses from another source

    let bound = 0
    for (const ip of localIPs) {
      this._createMDNSSocket(ip, () => {
        bound++
        if (bound === localIPs.length) {
          // All sockets bound — start periodic re-announce
          this._mdnsReannounce = setInterval(() => this._announceAll(), 30000)
        }
      })
    }
  }

  // _startDNSSD() was used to register via macOS dns-sd -R.  Disabled because
  // it caused TWO simultaneous mDNS responders (dns-sd + our hand-rolled code),
  // which produced conflicting responses that Pathport firmware discarded.
  // Hand-rolled mDNS with system hostname is now used exclusively.
  _startDNSSD() {
    // No-op — dns-sd disabled.  Hand-rolled mDNS handles everything.
  }

  _createMDNSSocket(ip, onComplete) {
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
      // Pin this socket to a single interface for sending AND receiving.
      try { sock.addMembership(MDNS_ADDR, ip) } catch (e) {
        this._log(`[RDMnet Broker] mDNS addMembership failed on ${ip}: ${e.message}`)
      }
      try { sock.setMulticastInterface(ip) } catch (e) {
        this._log(`[RDMnet Broker] mDNS setMulticastInterface failed on ${ip}: ${e.message}`)
      }
      try { sock.setMulticastTTL(255) }       catch (_) {}
      try { sock.setMulticastLoopback(false) } catch (_) {}

      this._mdnsSocks.push({ ip, sock })
      this.mDNSIPs.push(ip)
      const sysHost = brokerHostnameForIP(ip)
      this._log(`[RDMnet Broker] mDNS socket ready on ${ip} — hand-rolled mDNS, SRV→${sysHost}:${RDMNET_PORT}`)

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

            if (querierIP !== ip && !querierIP.startsWith('127.')) {
              const kind = isSubtypeQuery ? 'SUBTYPE' : 'GENERAL'
              this._log(`[RDMnet Broker] mDNS ${kind} query from ${querierIP} on ${ip}${queryDetail} — sending unicast+multicast response`)
              // Per RFC 6762, delay 20–120ms before responding to avoid collision.
              // We send BOTH unicast (to handle QU queries) AND multicast (for QM).
              setTimeout(() => {
                try {
                  const resp = buildSubtypePTRResponse(ip)
                  // Unicast: direct to querier on mDNS port
                  sock.send(resp, 0, resp.length, MDNS_PORT, querierIP, (err) => {
                    if (err) this._log(`[RDMnet Broker] unicast response error to ${querierIP}: ${err.message}`)
                    else this._log(`[RDMnet Broker] unicast response sent to ${querierIP} from ${ip} (${resp.length} bytes)`)
                  })
                  // Multicast: to 224.0.0.251 for QM queriers
                  sock.send(resp, 0, resp.length, MDNS_PORT, MDNS_ADDR, (err) => {
                    if (err) this._log(`[RDMnet Broker] multicast response error on ${ip}: ${err.message}`)
                  })
                } catch (e) {
                  this._log(`[RDMnet Broker] response build error: ${e.message}`)
                }
              }, 20 + Math.random() * 100)
            }
            // Track queriers to detect devices that query but never TCP connect
            if (!querierIP.startsWith('127.') && querierIP !== ip) {
              const q = this._mdnsQueriers.get(querierIP) || { firstSeen: Date.now(), queryCount: 0 }
              q.queryCount++
              this._mdnsQueriers.set(querierIP, q)
              // After 3+ queries from a device with no TCP connection, warn
              if (q.queryCount === 3) {
                const isConnected = [...this._clients.values()].some(c => c.connected && c.ip.includes(querierIP))
                if (!isConnected) {
                  // Detect which mDNS NIC this device lives on (for tcpdump hint)
                  const diagIface = ip
                  this._log(`[RDMnet Broker] ⚠ ${querierIP} has sent ${q.queryCount} mDNS queries but has NOT TCP connected.`)
                  this._log(`[RDMnet Broker]   The broker IS discoverable via mDNS — the device finds it but refuses to connect.`)
                  this._log(`[RDMnet Broker]   This almost always means a Pathscape configuration problem.`)
                  this._log(`[RDMnet Broker]`)
                  this._log(`[RDMnet Broker]   FIX IN PATHSCAPE (do BOTH steps, then Send All):`)
                  this._log(`[RDMnet Broker]    Step 1 — Protocol Support → check "Allow Unsecured Protocols"`)
                  this._log(`[RDMnet Broker]              (This is a MASTER GATE — without it, E1.33 Unsecured connections`)
                  this._log(`[RDMnet Broker]               are blocked at the firmware level even if E1.33 is selected.)`)
                  this._log(`[RDMnet Broker]    Step 2 — Properties → Network RDM Protocol → "E1.33 RDMnet (Unsecured)"`)
                  this._log(`[RDMnet Broker]    Step 3 — Click "Send All" to apply both settings`)
                  this._log(`[RDMnet Broker]    Step 4 — Wait ~30s, then run a new scan`)
                  this._log(`[RDMnet Broker]`)
                  this._log(`[RDMnet Broker]   IF PATHSCAPE IS ALREADY CONFIGURED CORRECTLY, run this in Terminal`)
                  this._log(`[RDMnet Broker]   to confirm whether the Pathport is even attempting TCP:`)
                  this._log(`[RDMnet Broker]     sudo tcpdump -i any -n 'tcp and port 5569 and host ${querierIP}'`)
                  this._log(`[RDMnet Broker]   Then click "Send All" in Pathscape. You should see a TCP SYN from ${querierIP}.`)
                  this._log(`[RDMnet Broker]   If no SYN appears, the firmware is blocking the connection internally.`)
                }
              }
            }
          } else {
            // Check if this is an A-record query for OUR per-interface hostname.
            // When the Pathport resolves the SRV target it got from our PTR response,
            // it will send an A query for rdmexplorer-<ip>.local.  We must answer this
            // ourselves — mDNSResponder has no record for this hostname and won't respond.
            const ourHostname = brokerHostnameForIP(ip)
            const aQuery = isAQueryForHostname(msg, ourHostname)
            if (aQuery && rinfo.address !== ip && !rinfo.address.startsWith('127.')) {
              this._log(`[RDMnet Broker] A-record query for ${ourHostname} from ${rinfo.address} — sending A response ${ip}`)
              const aResp = buildAResponse(ourHostname, ip)
              // Unicast back to querier (handles QU queries)
              sock.send(aResp, 0, aResp.length, MDNS_PORT, rinfo.address, (err) => {
                if (err) this._log(`[RDMnet Broker] A unicast error to ${rinfo.address}: ${err.message}`)
              })
              // Multicast too (handles QM queriers)
              sock.send(aResp, 0, aResp.length, MDNS_PORT, MDNS_ADDR, () => {})
            }

            // Check for A-record queries for our hostname (logging only)
            const otherQuery = describeOtherMDNSQuery(msg)
            if (otherQuery) {
              this._log(`[RDMnet Broker] mDNS hostname query from ${rinfo.address} on ${ip}: ${otherQuery}`)
            }
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
            }
          }
        } catch (_) {}
      })

      // Proactive unsolicited announcements — tells devices about the broker
      // without waiting for a query. Three announces: immediate, 1s, 5s.
      this._announceOn(sock, ip)
      setTimeout(() => this._announceOn(sock, ip), 1000)
      setTimeout(() => this._announceOn(sock, ip), 5000)

      if (onComplete) onComplete()
    })
  }

  _announceOn(sock, ip) {
    try {
      const announcement = buildMDNSAnnouncement(ip)
      sock.send(announcement, 0, announcement.length, MDNS_PORT, MDNS_ADDR, (err) => {
        if (err) this._log(`[RDMnet Broker] mDNS send error on ${ip}: ${err.message}`)
      })
    } catch (err) {
      this._log(`[RDMnet Broker] mDNS announce exception on ${ip}: ${err.message}`)
    }
  }

  _announceAll() {
    for (const { ip, sock } of this._mdnsSocks) this._announceOn(sock, ip)
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
