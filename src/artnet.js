/**
 * artnet.js
 * Handles Art-Net protocol: ArtPoll discovery and Art-RDM message transport.
 * Operates over UDP on port 6454.
 */

'use strict'

const dgram = require('dgram')
const EventEmitter = require('events')

const ARTNET_PORT = 6454
const ARTNET_HEADER = Buffer.from([0x41, 0x72, 0x74, 0x2D, 0x4E, 0x65, 0x74, 0x00]) // "Art-Net\0"
const PROTOCOL_VERSION = 14

const OP = {
  POLL:       0x2000,
  POLL_REPLY: 0x2100,
  RDM:        0x8002,
}

class ArtNet extends EventEmitter {
  constructor() {
    super()
    this.socket = null
  }

  /**
   * Bind the UDP socket and begin listening.
   * @param {string} bindAddress - Local IP to bind on (default 0.0.0.0)
   */
  start(bindAddress = '0.0.0.0') {
    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })

      this.socket.on('message', (msg, rinfo) => this._handleMessage(msg, rinfo))
      this.socket.on('error', (err) => { this.emit('error', err); reject(err) })

      this.socket.bind(ARTNET_PORT, bindAddress, () => {
        try { this.socket.setBroadcast(true) } catch (_) {}
        resolve()
      })
    })
  }

  stop() {
    if (this.socket) {
      try { this.socket.close() } catch (_) {}
      this.socket = null
    }
  }

  /** Broadcast an ArtPoll to find all nodes on the network. */
  sendArtPoll() {
    const buf = Buffer.alloc(14)
    ARTNET_HEADER.copy(buf, 0)
    buf.writeUInt16LE(OP.POLL, 8)
    buf.writeUInt16BE(PROTOCOL_VERSION, 10)
    buf.writeUInt8(0x02, 12) // TalkToMe: unicast replies on change
    buf.writeUInt8(0x00, 13) // Priority: DmxStartAddress
    this._send(buf, '255.255.255.255', ARTNET_PORT)
  }

  /**
   * Send an Art-RDM packet to a specific node.
   * @param {string} nodeIP   - Destination node IP
   * @param {number} net      - Universe net address (0-127)
   * @param {number} sub      - Universe sub-net (0-15)
   * @param {number} uni      - Universe (0-15)
   * @param {Buffer} rdmData  - Full RDM packet (including 0xCC start code)
   */
  sendArtRdm(nodeIP, net, sub, uni, rdmData) {
    const buf = Buffer.alloc(19 + rdmData.length)
    ARTNET_HEADER.copy(buf, 0)
    buf.writeUInt16LE(OP.RDM, 8)
    buf.writeUInt16BE(PROTOCOL_VERSION, 10)
    buf.writeUInt8(0x01, 12)                       // RdmVer
    buf.writeUInt8(0x01, 13)                       // Port (1-based)
    buf.writeUInt16BE(0x0000, 14)                  // Spare
    buf.writeUInt8(net & 0x7F, 16)                 // Net
    buf.writeUInt8(0x00, 17)                       // Command: ArProcess
    buf.writeUInt8(((sub & 0x0F) << 4) | (uni & 0x0F), 18) // Address
    rdmData.copy(buf, 19)
    this._send(buf, nodeIP, ARTNET_PORT)
  }

  _send(buf, address, port) {
    if (!this.socket) return
    this.socket.send(buf, 0, buf.length, port, address)
  }

  _handleMessage(msg, rinfo) {
    // Verify Art-Net header
    if (msg.length < 10) return
    if (!msg.slice(0, 8).equals(ARTNET_HEADER)) return

    const opCode = msg.readUInt16LE(8)

    switch (opCode) {
      case OP.POLL_REPLY:
        this.emit('artPollReply', this._parseArtPollReply(msg, rinfo))
        break
      case OP.RDM:
        // RDM payload starts at byte 19
        if (msg.length > 19) {
          this.emit('artRdmData', msg.slice(19), rinfo)
        }
        break
    }
  }

  _parseArtPollReply(msg, rinfo) {
    if (msg.length < 197) return { ip: rinfo.address, shortName: 'Unknown', longName: '', universes: [], supportsRDM: false }

    const netSwitch  = msg[18] & 0x7F
    const subSwitch  = msg[19] & 0x0F
    const shortName  = msg.slice(26, 44).toString('ascii').replace(/\0/g, '').trim()
    const longName   = msg.slice(44, 108).toString('ascii').replace(/\0/g, '').trim()
    const numPorts   = Math.min(msg[173], 4)          // Lo byte of NumPorts
    const portTypes  = [msg[174], msg[175], msg[176], msg[177]]
    const swOut      = [msg[190], msg[191], msg[192], msg[193]]
    const status1    = msg[23]

    // RDM support: Status1 bit 1, or assume true for Pathport (known RDM-capable nodes)
    const supportsRDM = !!(status1 & 0x02) || shortName.toLowerCase().includes('pathport')

    // Build universe list from output ports
    const universes = []
    for (let i = 0; i < numPorts; i++) {
      if (portTypes[i] & 0x80) { // bit 7 = output port
        universes.push({
          net:       netSwitch,
          sub:       subSwitch,
          uni:       swOut[i] & 0x0F,
          portIndex: i
        })
      }
    }

    // If no output ports reported, add a default universe 0.0.0
    if (universes.length === 0) {
      universes.push({ net: netSwitch, sub: subSwitch, uni: 0, portIndex: 0 })
    }

    return {
      ip: rinfo.address,
      shortName: shortName || `Node @ ${rinfo.address}`,
      longName,
      netSwitch,
      subSwitch,
      numPorts,
      universes,
      supportsRDM,
      status1,
      rawMsg: msg
    }
  }
}

module.exports = ArtNet
