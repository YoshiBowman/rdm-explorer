/**
 * sacn.js
 * sACN (ANSI E1.31) protocol handler.
 * Discovers sACN sources via multicast listening and Universe Discovery packets.
 * Uses UDP multicast on port 5568.
 */

'use strict'

const dgram = require('dgram')
const EventEmitter = require('events')

const SACN_PORT = 5568
const SACN_DISCOVERY_UNIVERSE = 64214

// ACN Packet Identifier (12 bytes): "ASC-E1.17\0\0\0"
const ACN_PACKET_ID = Buffer.from([
  0x41, 0x53, 0x43, 0x2D, 0x45, 0x31, 0x2E, 0x31, 0x37, 0x00, 0x00, 0x00
])

// Root layer vectors
const VECTOR_ROOT_E131_DATA     = 0x00000004
const VECTOR_ROOT_E131_EXTENDED = 0x00000008

// Framing layer vectors
const VECTOR_E131_DATA_PACKET          = 0x00000002
const VECTOR_E131_EXTENDED_DISCOVERY   = 0x00000002

// Universe Discovery layer vector
const VECTOR_UNIVERSE_DISCOVERY_LIST   = 0x00000001

/**
 * Convert a sACN universe number to its multicast address.
 * Universe N → 239.255.(N >> 8).(N & 0xFF)
 */
function universeToMulticast(universe) {
  return `239.255.${(universe >> 8) & 0xFF}.${universe & 0xFF}`
}

class SACN extends EventEmitter {
  constructor() {
    super()
    this.socket = null
    this.sources = new Map()   // CID hex string → source info
    this.joinedUniverses = new Set()
    this.running = false
  }

  /**
   * Bind the UDP socket, join discovery multicast, and begin listening.
   * @param {string} bindAddress - Local IP to bind on (default 0.0.0.0)
   */
  start(bindAddress = '0.0.0.0') {
    return new Promise((resolve, reject) => {
      this.running = true
      this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })

      this.socket.on('message', (msg, rinfo) => this._handleMessage(msg, rinfo))
      this.socket.on('error', (err) => this.emit('error', err))

      this.socket.bind(SACN_PORT, () => {
        // Join Universe Discovery multicast group
        try {
          const discoveryAddr = universeToMulticast(SACN_DISCOVERY_UNIVERSE)
          this.socket.addMembership(discoveryAddr)
          this.joinedUniverses.add(SACN_DISCOVERY_UNIVERSE)
        } catch (e) {
          this.emit('error', new Error(`sACN discovery multicast join failed: ${e.message}`))
        }

        // Join first 8 common universes to detect active sources
        for (let uni = 1; uni <= 8; uni++) {
          this.joinUniverse(uni)
        }

        resolve()
      })
    })
  }

  stop() {
    this.running = false
    if (this.socket) {
      try { this.socket.close() } catch (_) {}
      this.socket = null
    }
    this.sources.clear()
    this.joinedUniverses.clear()
  }

  /**
   * Join a specific universe's multicast group to listen for data.
   */
  joinUniverse(universe) {
    if (this.joinedUniverses.has(universe) || !this.socket) return
    try {
      this.socket.addMembership(universeToMulticast(universe))
      this.joinedUniverses.add(universe)
    } catch (_) {
      // Silently ignore — some interfaces don't support multicast
    }
  }

  _handleMessage(msg, rinfo) {
    if (msg.length < 38) return

    // Verify ACN packet identifier at offset 4
    if (!msg.slice(4, 16).equals(ACN_PACKET_ID)) return

    // Root layer vector at offset 18
    const rootVector = msg.readUInt32BE(18)
    // CID at offset 22 (16 bytes)
    const cid = msg.slice(22, 38).toString('hex')

    if (rootVector === VECTOR_ROOT_E131_DATA) {
      this._handleDataPacket(msg, rinfo, cid)
    } else if (rootVector === VECTOR_ROOT_E131_EXTENDED) {
      if (msg.length >= 44) {
        const framingVector = msg.readUInt32BE(40)
        if (framingVector === VECTOR_E131_EXTENDED_DISCOVERY) {
          this._handleDiscoveryPacket(msg, rinfo, cid)
        }
      }
    }
  }

  /**
   * Handle an E1.31 data packet — detect the source and its universe.
   */
  _handleDataPacket(msg, rinfo, cid) {
    if (msg.length < 126) return

    // Source name at offset 44 (64 bytes)
    const sourceName = msg.slice(44, 108).toString('utf8').replace(/\0/g, '').trim()
    const priority   = msg[108]
    const universe   = msg.readUInt16BE(113)

    this._registerSource(cid, rinfo.address, sourceName, [universe], priority)
  }

  /**
   * Handle an E1.31 Universe Discovery packet — learn all universes for a source.
   */
  _handleDiscoveryPacket(msg, rinfo, cid) {
    if (msg.length < 120) return

    const sourceName = msg.slice(44, 108).toString('utf8').replace(/\0/g, '').trim()

    // Universe Discovery layer: page at 118, last page at 119, list starts at 120
    const universes = []
    for (let i = 120; i + 1 < msg.length; i += 2) {
      const uni = msg.readUInt16BE(i)
      if (uni > 0 && uni <= 63999) {
        universes.push(uni)
      }
    }

    this._registerSource(cid, rinfo.address, sourceName, universes, 100)

    // Join newly discovered universes for deeper monitoring
    for (const uni of universes) {
      this.joinUniverse(uni)
    }
  }

  /**
   * Register or update a sACN source, emitting 'sourceFound' for new ones.
   */
  _registerSource(cid, ip, name, universes, priority) {
    const isNew = !this.sources.has(cid)

    const source = this.sources.get(cid) || {
      cid,
      ip,
      sourceName: name || `sACN Source @ ${ip}`,
      universes: new Set(),
      priority,
      lastSeen: Date.now(),
    }

    for (const u of universes) source.universes.add(u)
    source.lastSeen = Date.now()
    source.ip = ip
    if (name) source.sourceName = name

    this.sources.set(cid, source)

    if (isNew) {
      this.emit('sourceFound', this.formatSource(source))
    }
  }

  /**
   * Format a source object to match the node shape used by the UI.
   */
  formatSource(source) {
    const unis = Array.from(source.universes).sort((a, b) => a - b)
    return {
      cid:         source.cid,
      ip:          source.ip,
      shortName:   source.sourceName,
      longName:    source.sourceName,
      universes:   unis.map(u => ({ net: 0, sub: 0, uni: u, universe: u })),
      supportsRDM: false,   // sACN alone doesn't carry RDM — needs E1.33
      protocol:    'sacn',
      priority:    source.priority,
    }
  }

  /**
   * Return all currently known sources formatted for the UI.
   */
  getSources() {
    return Array.from(this.sources.values()).map(s => this.formatSource(s))
  }
}

module.exports = SACN
