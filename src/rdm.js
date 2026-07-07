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
  // Status collection (E1.20 §10.3)
  QUEUED_MESSAGE:                  0x0020,
  STATUS_MESSAGES:                 0x0030,
  STATUS_ID_DESCRIPTION:           0x0031,
  CLEAR_STATUS_ID:                 0x0032,
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
  // E1.37-7 — RDMnet gateway endpoint management (values verified against
  // ETCLabs/RDM rdm/defs.h).  Sent to a gateway's default responder (endpoint 0)
  // to enumerate its endpoints and the RDM responders it discovered on them.
  ENDPOINT_LIST:                   0x0900,
  ENDPOINT_LIST_CHANGE:            0x0901,
  IDENTIFY_ENDPOINT:               0x0902,
  ENDPOINT_TO_UNIVERSE:            0x0903,
  ENDPOINT_MODE:                   0x0904,
  ENDPOINT_LABEL:                  0x0905,
  RDM_TRAFFIC_ENABLE:              0x0906,
  DISCOVERY_STATE:                 0x0907,
  BACKGROUND_DISCOVERY:            0x0908,
  ENDPOINT_RESPONDERS:             0x090B,
  ENDPOINT_RESPONDER_LIST_CHANGE:  0x090C,
}

// ─── Product Categories ───────────────────────────────────────────────────────
// Source: ANSI E1.20 Table A-5 (via rdm-01788013.h)
const PRODUCT_CATEGORY = {
  0x0000: 'Not Declared',
  // Fixtures
  0x0100: 'Fixture',
  0x0101: 'Fixture — Fixed',
  0x0102: 'Fixture — Moving Yoke',
  0x0103: 'Fixture — Moving Mirror',
  0x01FF: 'Fixture — Other',
  // Fixture Accessories
  0x0200: 'Fixture Accessory',
  0x0201: 'Fixture Accessory — Color',        // Scrollers / Color Changers
  0x0202: 'Fixture Accessory — Yoke',         // Yoke add-on
  0x0203: 'Fixture Accessory — Mirror',       // Moving mirror add-on
  0x0204: 'Fixture Accessory — Effect',       // Effects discs
  0x0205: 'Fixture Accessory — Beam',         // Gobo rotators / iris / shutters / dousers / beam modifiers
  0x02FF: 'Fixture Accessory — Other',
  // Projectors
  0x0300: 'Projector',
  0x0301: 'Projector — Fixed',
  0x0302: 'Projector — Moving Yoke',
  0x0303: 'Projector — Moving Mirror',
  0x03FF: 'Projector — Other',
  // Atmospheric
  0x0400: 'Atmospheric',
  0x0401: 'Atmospheric — Effect',             // Fogger / hazer / flame
  0x0402: 'Atmospheric — Pyro',               // See E1.20 §A note
  0x04FF: 'Atmospheric — Other',
  // Dimmers
  0x0500: 'Dimmer',
  0x0501: 'Dimmer — AC Incandescent',
  0x0502: 'Dimmer — AC Fluorescent',
  0x0503: 'Dimmer — AC Cold Cathode',
  0x0504: 'Dimmer — AC Non-Dim',
  0x0505: 'Dimmer — AC ELV',
  0x0506: 'Dimmer — AC Other',
  0x0507: 'Dimmer — DC Level',
  0x0508: 'Dimmer — DC PWM',
  0x0509: 'Dimmer — CS LED',                  // Specialized LED dimmer
  0x05FF: 'Dimmer — Other',
  // Power
  0x0600: 'Power',
  0x0601: 'Power — Control',                  // Contactors / power controllers
  0x0602: 'Power — Source',                   // Generators
  0x06FF: 'Power — Other',
  // Scenic
  0x0700: 'Scenic',
  0x0701: 'Scenic — Drive',                   // Rotators / kabuki drops
  0x07FF: 'Scenic — Other',
  // Data
  0x0800: 'Data',
  0x0801: 'Data — Distribution',              // Splitters / repeaters / Ethernet products
  0x0802: 'Data — Conversion',                // Protocol conversion / analog decoders
  0x08FF: 'Data — Other',
  // AV
  0x0900: 'AV',
  0x0901: 'AV — Audio',
  0x0902: 'AV — Video',
  0x09FF: 'AV — Other',
  // Monitor
  0x0A00: 'Monitor',
  0x0A01: 'Monitor — AC Line Power',
  0x0A02: 'Monitor — DC Power',
  0x0A03: 'Monitor — Environmental',
  0x0AFF: 'Monitor — Other',
  // Control
  0x7000: 'Control',
  0x7001: 'Control — Controller',
  0x7002: 'Control — Backup Device',
  0x70FF: 'Control — Other',
  // Test
  0x7100: 'Test',
  0x7101: 'Test Equipment',
  0x71FF: 'Test Equipment — Other',
  // Misc
  0x7FFF: 'Other',
}

// ─── NACK Reason Codes ────────────────────────────────────────────────────────
// Source: ANSI E1.20 Table A-17 (via rdm-01788013.h)
// Returned in the PD of a NACK_REASON response (2-byte big-endian uint16).
const NACK_REASON = {
  0x0000: 'Unknown PID',
  0x0001: 'Format Error',
  0x0002: 'Hardware Fault',
  0x0003: 'Proxy Reject',
  0x0004: 'Write Protect',
  0x0005: 'Unsupported Command Class',
  0x0006: 'Data Out of Range',
  0x0007: 'Buffer Full',
  0x0008: 'Packet Size Unsupported',
  0x0009: 'Sub-Device Out of Range',
  0x000A: 'Proxy Buffer Full',
  0x000B: 'Action Not Supported',   // E1.37-2 extension
}

/**
 * Decode a NACK reason from a 2-byte PD buffer.
 * Returns a human-readable string, or a hex code for unknown reasons.
 */
function nackReasonString(pd) {
  if (!pd || pd.length < 2) return 'Unknown (no PD)'
  const code = pd.readUInt16BE(0)
  return NACK_REASON[code] || `Unknown (0x${code.toString(16).padStart(4, '0')})`
}

// ─── Sensor / Status / Lamp decode tables (E1.20 Appendix A) ──────────────────

// Table A-12 — sensor types (common subset; unknown values shown as hex)
const SENSOR_TYPE = {
  0x00: 'Temperature', 0x01: 'Voltage', 0x02: 'Current', 0x03: 'Frequency',
  0x04: 'Resistance', 0x05: 'Power', 0x06: 'Mass', 0x07: 'Length', 0x08: 'Area',
  0x09: 'Volume', 0x0A: 'Density', 0x0B: 'Velocity', 0x0C: 'Acceleration',
  0x0D: 'Force', 0x0E: 'Energy', 0x0F: 'Pressure', 0x10: 'Time', 0x11: 'Angle',
  0x12: 'Position X', 0x13: 'Position Y', 0x14: 'Position Z',
  0x15: 'Angular Velocity', 0x16: 'Luminous Intensity', 0x17: 'Luminous Flux',
  0x18: 'Illuminance', 0x19: 'Chrominance Red', 0x1A: 'Chrominance Green',
  0x1B: 'Chrominance Blue', 0x1C: 'Contacts', 0x1D: 'Memory', 0x1E: 'Items',
  0x1F: 'Humidity', 0x20: 'Counter 16-bit', 0x7F: 'Other',
}

// Table A-13 — sensor units (symbols)
const SENSOR_UNIT = {
  0x00: '', 0x01: '°C', 0x02: 'V DC', 0x03: 'V AC pk', 0x04: 'V AC RMS',
  0x05: 'A DC', 0x06: 'A AC pk', 0x07: 'A AC RMS', 0x08: 'Hz', 0x09: 'Ω',
  0x0A: 'W', 0x0B: 'kg', 0x0C: 'm', 0x0D: 'm²', 0x0E: 'm³', 0x0F: 'kg/m³',
  0x10: 'm/s', 0x11: 'm/s²', 0x12: 'N', 0x13: 'J', 0x14: 'Pa', 0x15: 's',
  0x16: '°', 0x17: 'sr', 0x18: 'cd', 0x19: 'lm', 0x1A: 'lx', 0x1B: 'IRE', 0x1C: 'B',
}

// Table A-14 — unit prefix → multiplier
const SENSOR_PREFIX_MULT = {
  0x00: 1, 0x01: 1e-1, 0x02: 1e-2, 0x03: 1e-3, 0x04: 1e-6, 0x05: 1e-9,
  0x06: 1e-12, 0x07: 1e-15, 0x08: 1e-18, 0x09: 1e-21, 0x0A: 1e-24,
  0x11: 10, 0x12: 100, 0x13: 1e3, 0x14: 1e6, 0x15: 1e9, 0x16: 1e12,
  0x17: 1e15, 0x18: 1e18, 0x19: 1e21, 0x1A: 1e24,
}

// Lamp states (E1.20 Table A-8)
const LAMP_STATE_NAME = {
  0x00: 'Off', 0x01: 'On', 0x02: 'Striking', 0x03: 'Standby',
  0x04: 'Not Present', 0x05: 'Error', 0x7F: 'No Lamp',
}

// Status types (E1.20 Table A-4)
const STATUS_TYPE_NAME = {
  0x00: 'None', 0x01: 'Get Last', 0x02: 'Advisory', 0x03: 'Warning', 0x04: 'Error',
  0x12: 'Advisory (cleared)', 0x13: 'Warning (cleared)', 0x14: 'Error (cleared)',
}

// Standard status message IDs (E1.20 Table B-5, subset).  %d1/%d2 are the
// two data values carried with the message.
const STATUS_MESSAGE_TEXT = {
  0x0001: 'Calibration failed (slot %d1)',
  0x0002: 'Sensor %d1 not found',
  0x0003: 'Sensor %d1 always on',
  0x0011: 'Lamp doused',
  0x0012: 'Lamp failed to strike',
  0x0021: 'Over-temperature: %d1 °C (sensor %d2)',
  0x0022: 'Under-temperature: %d1 °C (sensor %d2)',
  0x0023: 'Sensor %d1 out of range',
  0x0031: 'Over-voltage: %d1 V (phase %d2)',
  0x0032: 'Under-voltage: %d1 V (phase %d2)',
  0x0033: 'Over-current: %d1 A (phase %d2)',
  0x0034: 'Under-current: %d1 A (phase %d2)',
  0x0035: 'Phase %d1: %d2°',
  0x0036: 'Phase %d1 error',
  0x0037: 'Current: %d1 A',
  0x0038: 'Voltage: %d1 V',
  0x0041: 'No dimmer response',
  0x0042: 'Load failure',
  0x0043: 'Breaker tripped',
  0x0044: 'Watts: %d1 W',
  0x0045: 'Dimmer failure',
  0x0046: 'Dimmer panic mode',
  0x0050: 'Ready',
  0x0051: 'Not ready',
  0x0052: 'Low fluid',
}

/**
 * Format a status message into human-readable text.
 * Manufacturer-specific IDs (>= 0x8000) are shown as hex with raw data values.
 */
function statusMessageText(msgId, d1, d2) {
  const tpl = STATUS_MESSAGE_TEXT[msgId]
  if (tpl) return tpl.replace('%d1', String(d1)).replace('%d2', String(d2))
  return `Mfr status 0x${msgId.toString(16).toUpperCase().padStart(4, '0')} (data ${d1}, ${d2})`
}

/**
 * Parse a SENSOR_DEFINITION response PD (E1.20 §10.7.1).
 */
function parseSensorDefinition(pd) {
  if (!pd || pd.length < 13) return null
  return {
    num:        pd[0],
    type:       pd[1],
    typeName:   SENSOR_TYPE[pd[1]] || `0x${pd[1].toString(16)}`,
    unit:       SENSOR_UNIT[pd[2]] !== undefined ? SENSOR_UNIT[pd[2]] : '',
    prefixMult: SENSOR_PREFIX_MULT[pd[3]] !== undefined ? SENSOR_PREFIX_MULT[pd[3]] : 1,
    rangeMin:   pd.readInt16BE(4),
    rangeMax:   pd.readInt16BE(6),
    normalMin:  pd.readInt16BE(8),
    normalMax:  pd.readInt16BE(10),
    recorded:   pd[12],              // bit 0: recorded value support, bit 1: lowest/highest
    description: pd.length > 13 ? pd.slice(13).toString('ascii').replace(/\0.*$/, '').trim() : '',
  }
}

/**
 * Parse a SENSOR_VALUE response PD (E1.20 §10.7.2).
 */
function parseSensorValue(pd) {
  if (!pd || pd.length < 9) return null
  return {
    num:      pd[0],
    present:  pd.readInt16BE(1),
    lowest:   pd.readInt16BE(3),
    highest:  pd.readInt16BE(5),
    recorded: pd.readInt16BE(7),
  }
}

/**
 * Parse a STATUS_MESSAGES response PD (E1.20 §10.3.1) — N × 9-byte entries.
 */
function parseStatusMessages(pd) {
  const out = []
  if (!pd) return out
  for (let off = 0; off + 9 <= pd.length; off += 9) {
    const subDevice = pd.readUInt16BE(off)
    const type      = pd[off + 2]
    const msgId     = pd.readUInt16BE(off + 3)
    const d1        = pd.readInt16BE(off + 5)
    const d2        = pd.readInt16BE(off + 7)
    out.push({
      subDevice, type,
      typeName: STATUS_TYPE_NAME[type] || `0x${type.toString(16)}`,
      msgId, d1, d2,
      text: statusMessageText(msgId, d1, d2),
    })
  }
  return out
}

// ─── Response Type Helpers ────────────────────────────────────────────────────
const RESPONSE_TYPE = {
  ACK:          0x00,
  ACK_TIMER:    0x01,
  NACK_REASON:  0x02,
  ACK_OVERFLOW: 0x03,
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
  CC, PID, PRODUCT_CATEGORY, NACK_REASON, RESPONSE_TYPE,
  SENSOR_TYPE, SENSOR_UNIT, LAMP_STATE_NAME, STATUS_TYPE_NAME,
  SOURCE_UID, BROADCAST_UID, ALL_DEVICES,
  buildPacket, buildDiscUniqueBranch, buildDiscMute, buildDiscUnMuteAll,
  buildGetRequest, buildSetRequest,
  parsePacket, parseDiscoveryResponse, parseDeviceInfo,
  parseSensorDefinition, parseSensorValue, parseStatusMessages, statusMessageText,
  nackReasonString,
  uidToString, stringToUID,
  checksum, nextTN,
}
