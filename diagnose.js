#!/usr/bin/env node
/**
 * diagnose.js  —  Art-Net discovery diagnostic
 *
 * Run this OUTSIDE the app from your terminal:
 *   cd ~/Documents/rdm-explorer
 *   node diagnose.js
 *
 * If this finds your nodes but the app doesn't → Electron firewall/sandbox issue.
 * If sudo finds nodes but node doesn't         → macOS firewall is blocking node.
 * If neither finds nodes                       → network / subnet / node config issue.
 */
'use strict'

const dgram = require('dgram')
const os    = require('os')

const ARTNET_PORT   = 6454
const ARTNET_HEADER = Buffer.from([0x41, 0x72, 0x74, 0x2D, 0x4E, 0x65, 0x74, 0x00])

// ── Print all NICs and compute their subnet broadcasts ──────────────────────
const broadcasts = new Set(['255.255.255.255'])
console.log('\n── Network Interfaces ────────────────────────────────────────────')
for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
  for (const addr of addrs) {
    if (addr.family === 'IPv4' && !addr.internal) {
      const ipParts   = addr.address.split('.').map(Number)
      const maskParts = addr.netmask.split('.').map(Number)
      const bc = ipParts.map((o, i) => (o | (~maskParts[i] & 0xFF))).join('.')
      console.log(`  ${name.padEnd(14)} ${addr.address.padEnd(18)} subnet bc → ${bc}`)
      broadcasts.add(bc)
    }
  }
}

// ── Build ArtPoll packets with different TalkToMe values to try ─────────────
function makePoll(talkToMe) {
  const buf = Buffer.alloc(14)
  ARTNET_HEADER.copy(buf, 0)
  buf.writeUInt16LE(0x2000, 8)   // OpPoll
  buf.writeUInt16BE(14,    10)   // Protocol version 14
  buf.writeUInt8(talkToMe, 12)
  buf.writeUInt8(0x00,     13)   // Priority
  return buf
}

// ── Create socket ───────────────────────────────────────────────────────────
const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })
let packetCount = 0
const seenIPs = new Set()

function describePacket(msg, rinfo) {
  if (msg.length < 10 || !msg.slice(0, 8).equals(ARTNET_HEADER)) {
    return `  Non-Art-Net UDP from ${rinfo.address} (${msg.length}b)`
  }
  const opCode = msg.readUInt16LE(8)
  switch (opCode) {
    case 0x2100: {
      if (msg.length >= 44) {
        const shortName = msg.slice(26, 44).toString('ascii').replace(/\0/g, '').trim()
        const longName  = msg.slice(44, 108).toString('ascii').replace(/\0/g, '').trim()
        const status1   = msg.length > 23 ? `status=0x${msg[23].toString(16)}` : ''
        return `  ✅ ArtPollReply from ${rinfo.address}\n     Name: "${shortName}" / "${longName}"  ${status1}`
      }
      return `  ✅ ArtPollReply from ${rinfo.address} (short packet, ${msg.length}b)`
    }
    case 0x2000: return `  OpPoll (0x2000) from ${rinfo.address} — node is also scanning`
    case 0x5000: {
      const seq  = msg.length > 12 ? msg[12] : '?'
      const uni  = msg.length > 15 ? msg.readUInt16LE(14) : '?'
      const len  = msg.length > 17 ? msg.readUInt16BE(16) : '?'
      return `  ArtDmx (0x5000) from ${rinfo.address} — universe ${uni}, ${len} channels, seq ${seq}`
    }
    case 0x8100: return `  ArtTodData (0x8100) from ${rinfo.address} — RDM table of devices`
    case 0x8000: return `  ArtTodRequest (0x8000) from ${rinfo.address}`
    case 0x8300: return `  ArtRdm (0x8300) from ${rinfo.address}`
    default:     return `  Art-Net 0x${opCode.toString(16).padStart(4,'0')} from ${rinfo.address} (${msg.length}b)`
  }
}

socket.on('message', (msg, rinfo) => {
  packetCount++
  const desc = describePacket(msg, rinfo)
  // Deduplicate noisy ArtDmx lines — only print first occurrence per IP+uni
  const opCode = msg.length >= 10 && msg.slice(0, 8).equals(ARTNET_HEADER) ? msg.readUInt16LE(8) : 0
  const key = opCode === 0x5000 ? `dmx-${rinfo.address}-${msg.length > 15 ? msg.readUInt16LE(14) : 0}` : null
  if (key) {
    if (seenIPs.has(key)) return  // suppress repeated ArtDmx spam
    seenIPs.add(key)
  }
  // Track unique source IPs and poll replies
  seenIPs.add(`ip-${rinfo.address}`)
  if (opCode === 0x2100) seenIPs.add(`reply-${rinfo.address}`)
  console.log(desc)
})

socket.on('error', (err) => {
  console.error('\n✗ Socket error:', err.message)
  if (err.code === 'EADDRINUSE') {
    console.error('  Port 6454 is already bound. Check: sudo lsof -i :6454')
  }
  process.exit(1)
})

socket.bind(ARTNET_PORT, '0.0.0.0', () => {
  socket.setBroadcast(true)
  console.log(`\n── Socket bound to 0.0.0.0:${ARTNET_PORT} ✓`)

  // ── Phase 1: broadcast ArtPoll with TalkToMe 0x00 and 0x02 ───────────────
  console.log('\n── Phase 1: Broadcast ArtPoll (TalkToMe=0x00 and 0x02) ────────────')
  for (const bc of broadcasts) {
    socket.send(makePoll(0x00), 0, 14, ARTNET_PORT, bc, (err) => {
      if (err) console.log(`  ✗ TalkToMe=0x00 → ${bc}: ${err.message}`)
      else     console.log(`  ✓ TalkToMe=0x00 → ${bc}`)
    })
    socket.send(makePoll(0x02), 0, 14, ARTNET_PORT, bc, (err) => {
      if (!err) console.log(`  ✓ TalkToMe=0x02 → ${bc}`)
    })
    socket.send(makePoll(0x06), 0, 14, ARTNET_PORT, bc, (err) => {
      if (!err) console.log(`  ✓ TalkToMe=0x06 → ${bc}`)
    })
  }

  console.log('\n── Listening (3s)… ────────────────────────────────────────────────')

  // ── Phase 2: unicast sweep of custom subnet (from CLI arg) + known IPs ──────
  setTimeout(async () => {
    const customSubnet = process.argv[2] || ''  // e.g. node diagnose.js 10.30.142
    const myIPs = new Set(Object.values(os.networkInterfaces()).flat().map(a => a.address))

    if (customSubnet && customSubnet.split('.').length === 3) {
      console.log(`\n── Phase 2: Unicast sweep of ${customSubnet}.1–254 ──────────────────`)
      let sent = 0
      for (let h = 1; h <= 254; h++) {
        const ip = `${customSubnet}.${h}`
        socket.send(makePoll(0x00), 0, 14, ARTNET_PORT, ip)
        socket.send(makePoll(0x02), 0, 14, ARTNET_PORT, ip)
        sent++
        if (h % 50 === 0) {
          await new Promise(r => setTimeout(r, 10))
          process.stdout.write(`  ... sent to ${ip}\n`)
        }
      }
      console.log(`  ✓ Sent ArtPoll to all ${sent} hosts in ${customSubnet}.0/24`)
    } else {
      console.log('\n── Phase 2: Unicast ArtPoll to known node IPs ──────────────────────')
      console.log('  (Tip: pass a subnet as argument to sweep it, e.g.: node diagnose.js 10.30.142)')
      const knownTargets = [
        '10.0.0.55','10.0.0.59','10.0.0.75','10.0.0.85','10.0.0.115',
        '10.0.3.11','10.0.5.2','10.0.7.134','10.0.7.251',
        '10.0.7.5','10.0.7.211','10.0.4.54','10.0.3.238','10.0.6.185',
        '10.0.2.180','10.0.4.231','10.0.7.176','10.0.7.59',
      ].filter(ip => !myIPs.has(ip))
      for (const ip of knownTargets) {
        socket.send(makePoll(0x00), 0, 14, ARTNET_PORT, ip)
        socket.send(makePoll(0x02), 0, 14, ARTNET_PORT, ip)
        console.log(`  ✓ Sent to ${ip}`)
      }
    }
    console.log('\n── Listening for replies (4s)… ─────────────────────────────────────')
  }, 3000)

  // ── Phase 3: final summary ────────────────────────────────────────────────
  setTimeout(() => {
    socket.close()
    const pollReplies = [...seenIPs].filter(k => k.startsWith('reply-')).length
    const uniqueSources = [...seenIPs].filter(k => k.startsWith('ip-')).map(k => k.slice(3))
    console.log(`\n── Done — ${packetCount} total packets, sources: ${uniqueSources.join(', ')}\n`)

    if (pollReplies === 0) {
      console.log('⚠️  Zero ArtPollReply (0x2100) received — even from unicast to known nodes.')
      console.log()
      console.log('   Most likely causes:')
      console.log('   1. Nodes are locked to the console only (Pathport "Restrict to primary controller" setting)')
      console.log('   2. Nodes are behind a managed switch with ArtPoll blocked (IGMP snooping, VLAN)')
      console.log('   3. Your Mac needs to be on the 2.x.x.x Art-Net subnet to be recognized')
      console.log()
      console.log('   What to try:')
      console.log('   → Log into a Pathport node web UI (e.g. http://10.0.0.55) and check its')
      console.log('     "Network Security" or "Controller" settings')
      console.log('   → Ask your network admin if there is VLAN isolation or managed switch config')
    }
  }, 7500)
})
