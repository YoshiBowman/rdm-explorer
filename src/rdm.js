/**
 * rdm.js
 * RDM (ANSI E1.20) protocol: packet building, parsing, constants.
 * Implements the core packet structure used for discovery and device control.
 */

'use strict'

// ─── Command Classes ──────────────────────────────────────────────────────────
const CC = {
  DISC_COMMAND:          0x10,
  DISC_COMMAND_RESPONSE: 0x11,
  GET_COMMAND:           0x20,
  GET_COMMAND_RESPONSE:  0x21,
  SET_COMMAND:           0x30,
  SET_COMMAND_RESPONSE:  0x31,
}

// ─── Parameter IDs ───────────────────────────────────────────────────────────
const PID = {
  // Discovery
  DISC_UNIQUE_BRANCH:              0x0001,
  DISC_MUTE:                       0x0002,
  DISC_UN_MUTE:                    0x0003,
  // Device info
  SUPPORTED_PARAMETERS:            0x0050,
  DEVICE_INFO:                     0x0060,
  DEVICE_MODEL_DESCRIPTION:        0x0080,
  MANUFACTURER_LABEL:              0x0081,
  DEVICE_LABEL:                    0x0082,
  SOFTWARE_VERSION_LABEL:          0x00C0,
  // DMX
  DMX_PERSONALITY:                 0x00E0,
  DMX_PERSONALITY_DESCRIPTION:     0x00E1,
  DMX_START_ADDRESS:               0x00F0,
  // Sensors / diagnostics
  SENSOR_DEFINITION:               0x0200,
  SENSOR_VALUE:                    0x0201,
  DEVICE_HOURS:                    0x0400,
  LAMP_HOURS:                      0x0401,
  LAMP_STRIKES:                    0x0402,
  LAMP_STATE:                      0x0403,
  DEVICE_POWER_CYCLES:             0x0405,
  // Control
  IDENTIFY_DEVICE:                 0x1000,
  RESET_DEVICE:                    0x1001,
  POWER_STATE:                     0x1010,
}

// ─── Product Categories ───────────────────────────────────────────────────────
const PRODUCT_CATEGORY = {
  0x0000: 'Not Declared',
  0x0100: 'Fixture',
  0x0101: 'Fixture — Fixed',
  0x0102: 'Fixture — Moving Yoke',
  0x0103: 'Fixture — Moving Mirror',
  0x01FF: 'Fixture — Other',
  0x0200: 'Fixture Accessory',
  0x0201: 'Fixture Accessory — Color Scroll',
  0x0202: 'Fixture Accessory — Color Wheel',
  0x0203: 'Fixture Accessory — Dimmer',
  0x0204: 'Fixture Accessory — Effect',
  0x0205: 'Fixture Accessory — Gobo Rotator',
  0x02FF: 'Fixture Accessory — Other',
  0x0300: 'Projector',
  0x0400: 'Atmospheric',
  0x0401: 'Atmospheric — Fog',
  0x0402: 'Atmospheric — Haze',
  0x04FF: 'Atmospheric — Other',
  0x0500: 'Dimmer',
  0x0501: 'Dimmer — AC Incandescent',
  0x0502: 'Dimmer — AC Fluorescent',
  0x0503: 'Dimmer — AC Cold Cathode',
  0x0504: 'Dimmer — AC Non-Dim',
  0x0505: 'Dimmer — AC ELV',
  0x0506: 'Dimmer — AC Other',
  0x0507: 'Dimmer — DC Level',
  0x0508: 'Dimmer — DC PWM',
  0x05FF: 'Dimmer — Other',
  0x0600: 'Power',
  0x0700: 'Scenic',
  0x0800: 'Data',
  0x0900: 'AV',
  0x0A00: 'Monitor',
  0x7000: 'Control',
  0x7001: 'Control — Network',
  0x7002: 'Control — Source Four',
  0x7003: 'Control — Fiber',
  0x7FFF: 'Other',
}

// ─── UIDs ─────────────────────────────────────────────────────────────────────
// Our controller uses manufacturer ID 0x7FF0 (prototype range)
const SOURCE_UID    = Buffer.from([0x7F, 0xF0, 0x00, 0x00, 0x00, 0x01])
const BROADCAST_UID = Buffer.from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
const ALL_DEVICES   = Buffer.from([0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00])

// ─── Checksum ────────────────────────────────────────────────────────────────
function checksum(buf, len) {
  let sum = 0
  for (let i = 0; i < len; i++) sum += buf[i]
  return sum & 0xFFFF
}

// ─── Packet Builder ───────────────────────────────────────────────────────────
let _tn = 0
function nextTN() { _tn = (_tn + 1) & 0xFF; return _tn }

/**
 * Build a complete RDM packet including start code and checksum.
 */
function buildPacket({ destUID, srcUID, tn, portId = 1, msgCount = 0, subDevice = 0, cc, pid, pd }) {
  pd = pd || Buffer.alloc(0)
  const msgLen = 24 + pd.length  // length field covers SC through end of PD
  const total  = msgLen + 2       // + 2 for checksum

  const buf = Buffer.alloc(total)
  let o = 0

  buf[o++] = 0xCC          // Start Code
  buf[o++] = 0x01          // Sub-Start Code
  buf[o++] = msgLen        // Message Length

  destUID.copy(buf, o); o += 6
  srcUID.copy(buf, o);  o += 6

  buf[o++] = tn & 0xFF
  buf[o++] = portId & 0xFF
  buf[o++] = msgCount & 0xFF
  buf.writeUInt16BE(subDevice & 0xFFFF, o); o += 2
  buf[o++] = cc & 0xFF
  buf.writeUInt16BE(pid & 0xFFFF, o); o += 2
  buf[o++] = pd.length & 0xFF

  pd.copy(buf, o); o += pd.length

  buf.writeUInt16BE(checksum(buf, msgLen), msgLen)
  return buf
}

// ─── Discovery Packets ────────────────────────────────────────────────────────
function buildDiscUniqueBranch(lower, upper) {
  return buildPacket({
    destUID: BROADCAST_UID, srcUID: SOURCE_UID,
    tn: 0, cc: CC.DISC_COMMAND, pid: PID.DISC_UNIQUE_BRANCH,
    pd: Buffer.concat([lower, upper])
  })
}

function buildDiscMute(uid) {
  return buildPacket({
    destUID: uid, srcUID: SOURCE_UID,
    tn: nextTN(), cc: CC.DISC_COMMAND, pid: PID.DISC_MUTE,
    pd: Buffer.alloc(0)
  })
}

function buildDiscUnMuteAll() {
  return buildPacket({
    destUID: BROADCAST_UID, srcUID: SOURCE_UID,
    tn: nextTN(), cc: CC.DISC_COMMAND, pid: PID.DISC_UN_MUTE,
    pd: Buffer.alloc(0)
  })
}

// ─── GET / SET Packets ────────────────────────────────────────────────────────
function buildGetRequest(uid, pid, pd = null) {
  return buildPacket({
    destUID: uid, srcUID: SOURCE_UID,
    tn: nextTN(), cc: CC.GET_COMMAND, pid,
    pd: pd || Buffer.alloc(0)
  })
}

function buildSetRequest(uid, pid, pd) {
  return buildPacket({
    destUID: uid, srcUID: SOURCE_UID,
    tn: nextTN(), cc: CC.SET_COMMAND, pid, pd
  })
}

// ─── Packet Parser ────────────────────────────────────────────────────────────
function parsePacket(buf) {
  if (!buf || buf.length < 26) return null
  if (buf[0] !== 0xCC || buf[1] !== 0x01) return null

  const msgLen = buf[2]
  if (buf.length < msgLen + 2) return null

  let o = 3
  const destUID = buf.slice(o, o + 6); o += 6
  const srcUID  = buf.slice(o, o + 6); o += 6
  const tn           = buf[o++]
  const responseType = buf[o++]
  const msgCount     = buf[o++]
  const subDevice    = buf.readUInt16BE(o); o += 2
  const cc           = buf[o++]
  const pid          = buf.readUInt16BE(o); o += 2
  const pdLen        = buf[o++]
  const pd           = buf.slice(o, o + pdLen)

  const expectedCS = checksum(buf, msgLen)
  const actualCS   = buf.readUInt16BE(msgLen)

  return {
    destUID,
    srcUID:        uidToString(srcUID),
    srcUIDBuffer:  srcUID,
    tn, responseType, msgCount, subDevice, cc, pid, pdLen, pd,
    csValid: expectedCS === actualCS
  }
}

/**
 * Parse the encoded preamble response from DISC_UNIQUE_BRANCH.
 * Returns a 6-byte UID buffer, or null if invalid.
 */
function parseDiscoveryResponse(buf) {
  if (!buf || buf.length < 17) return null

  // Skip preamble bytes (0xFE)
  let i = 0
  while (i < buf.length && buf[i] === 0xFE) i++
  if (i >= buf.length || buf[i] !== 0xAA) return null
  i++ // skip separator

  if (buf.length - i < 16) return null

  const encoded = buf.slice(i, i + 16)
  const decoded = Buffer.alloc(8)
  for (let j = 0; j < 8; j++) {
    decoded[j] = (encoded[j * 2] & 0xAA) | (encoded[j * 2 + 1] & 0x55)
  }

  const uid = decoded.slice(0, 6)
  const cs  = (decoded[6] << 8) | decoded[7]
  let sum   = 0
  for (let j = 0; j < 6; j++) sum += uid[j]
  if ((sum & 0xFFFF) !== cs) return null

  return uid
}

// ─── UID Helpers ─────────────────────────────────────────────────────────────
function uidToString(uid) {
  const mfr = uid.readUInt16BE(0).toString(16).padStart(4, '0').toUpperCase()
  const dev = uid.readUInt32BE(2).toString(16).padStart(8, '0').toUpperCase()
  return `${mfr}:${dev}`
}

function stringToUID(str) {
  const hex = str.replace(':', '').replace(/\s/g, '')
  if (hex.length !== 12) throw new Error(`Invalid UID string: ${str}`)
  return Buffer.from(hex, 'hex')
}

// ─── DEVICE_INFO parser ──────────────────────────────────────────────────────
function parseDeviceInfo(pd) {
  if (!pd || pd.length < 19) return null
  return {
    rdmProtocolVersion:  pd.readUInt16BE(0),
    deviceModelId:       pd.readUInt16BE(2),
    productCategory:     pd.readUInt16BE(4),
    productCategoryName: PRODUCT_CATEGORY[pd.readUInt16BE(4)] || 'Unknown',
    softwareVersionId:   pd.readUInt32BE(6),
    dmxFootprint:        pd.readUInt16BE(10),
    currentPersonality:  pd[12],
    personalityCount:    pd[13],
    dmxStartAddress:     pd.readUInt16BE(14),
    subDeviceCount:      pd.readUInt16BE(16),
    sensorCount:         pd[18],
  }
}

module.exports = {
  CC, PID, PRODUCT_CATEGORY,
  SOURCE_UID, BROADCAST_UID, ALL_DEVICES,
  buildPacket, buildDiscUniqueBranch, buildDiscMute, buildDiscUnMuteAll,
  buildGetRequest, buildSetRequest,
  parsePacket, parseDiscoveryResponse, parseDeviceInfo,
  uidToString, stringToUID,
  checksum, nextTN,
}
