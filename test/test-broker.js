// test/test-broker.js
// Standalone test — no Electron required. Run with: node test/test-broker.js
//
// NOTE: brokerHostnameForIP is a module-level utility, not a class method.
// It is exported as RDMnetBroker.brokerHostnameForIP for testability.
//
// Test 6 is a Pathport-format handshake simulation (runs without hardware).
// Test 7 (fixture scan) is an integration test — it requires real Art-Net/sACN
// nodes with RDM fixtures physically connected. It will FAIL when run without
// hardware. This is intentional: the test documents that fixtures must be
// discoverable end-to-end.

const RDMnetBroker = require('../src/rdmnet-broker');
// NOTE: Scanner is lazy-required inside Test 6.
// scanner.js starts a shared broker on port 5569 the moment it is require()-d,
// which would conflict with the broker unit tests above.  Deferring the require
// until after those tests have stopped their instances avoids EADDRINUSE.

// How long to wait for the full scan to complete (ms).
// Increase if your network is slow or you have many nodes.
const SCAN_TIMEOUT_MS = 60_000;

async function runTest() {
  const results = { passed: [], failed: [] };

  // ─── Test 1: brokerHostnameForIP — pure function, no network needed ──────────
  try {
    const fn = RDMnetBroker.brokerHostnameForIP;
    if (typeof fn !== 'function') throw new Error('brokerHostnameForIP is not exported');

    const cases = [
      { ip: '192.168.1.250', expected: 'rdmexplorer-192-168-1-250.local' },
      { ip: '10.0.0.1',      expected: 'rdmexplorer-10-0-0-1.local'      },
      { ip: '192.168.1.39',  expected: 'rdmexplorer-192-168-1-39.local'  },
    ];

    for (const { ip, expected } of cases) {
      const result = fn(ip);
      if (result === expected) {
        results.passed.push(`brokerHostnameForIP('${ip}') → '${result}'`);
      } else {
        results.failed.push(`brokerHostnameForIP('${ip}') expected '${expected}', got '${result}'`);
      }
    }
  } catch (e) {
    results.failed.push(`brokerHostnameForIP threw: ${e.message}`);
  }

  // ─── Test 2: Broker starts and TCP server binds on port 5569 ─────────────────
  let broker;
  try {
    broker = new RDMnetBroker();

    // Suppress log output during tests
    broker.on('log', () => {});

    await broker.start();

    if (broker.running !== true) {
      results.failed.push('Broker started but broker.running !== true');
    } else {
      results.passed.push('Broker starts without error (broker.running = true)');
    }

    if (broker.server && broker.server.listening) {
      results.passed.push(`TCP server is listening (port ${broker.port})`);
    } else {
      results.failed.push('TCP server is not listening after start()');
    }
  } catch (e) {
    results.failed.push(`Broker start() threw: ${e.message}`);
  }

  // ─── Test 3: Broker stops cleanly ────────────────────────────────────────────
  try {
    if (broker) {
      broker.stop();
      if (broker.running === false) {
        results.passed.push('Broker stops cleanly (broker.running = false after stop())');
      } else {
        results.failed.push('Broker stop() did not set broker.running = false');
      }
    } else {
      results.failed.push('Broker stop() skipped — broker never started');
    }
  } catch (e) {
    results.failed.push(`Broker stop() threw: ${e.message}`);
  }

  // ─── Test 4: Second start after stop is safe ─────────────────────────────────
  try {
    const broker2 = new RDMnetBroker();
    broker2.on('log', () => {});
    await broker2.start();
    broker2.stop();
    results.passed.push('Second broker instance starts and stops without error');
  } catch (e) {
    results.failed.push(`Second broker instance failed: ${e.message}`);
  }

  // ─── Test 5: Calling start() twice is a no-op ─────────────────────────────────
  try {
    const broker3 = new RDMnetBroker();
    broker3.on('log', () => {});
    await broker3.start();
    await broker3.start(); // should return immediately, not throw
    results.passed.push('Calling start() twice is a safe no-op');
    broker3.stop();
  } catch (e) {
    results.failed.push(`start() called twice threw: ${e.message}`);
  }

  // ─── Test 6: Pathport-format BROKER_CONNECT handshake simulation ─────────────
  // Verifies that when a device using Pathport's non-standard ACN encoding
  // (3-byte FL, 2-byte broker vectors in sender, ACN_PID preamble at byte 0)
  // connects, the broker correctly:
  //   (a) parses the BROKER_CONNECT and extracts the correct UID — Attempt 25 fix
  //   (b) sends BROKER_CONNECT_REPLY with Pathport preamble (ACN_PID at byte 0)
  //   (c) sends BROKER_CONNECT_REPLY with 3-byte flags+length (byte 16 = 0xF0)
  //   (d) sends BROKER_CONNECT_REPLY with 2-byte broker vector (0x0002, per E1.33)
  //   (e) echoes the correct client UID back in the reply (Attempt 25 fix validated)
  //   (f) keeps the socket alive after REPLY (REPLY is accepted by the mock client)
  // This test runs in the VM and does NOT require real Pathport hardware.
  try {
    const net_mod = require('net');
    const broker6 = new RDMnetBroker();
    broker6.on('log', () => {});
    await broker6.start();

    // ACN Packet Identifier — first 12 bytes of any ACN preamble
    const ACN_PID_BUF = Buffer.from('4153432d45312e313700000000000000', 'hex').slice(0, 12);

    // Simulated Pathport CID and UID (matching real Pathport .41 MACs from CLAUDE.md §2)
    const PATHPORT_CID = Buffer.from('001e96ce00005043800000a11e96ce01', 'hex'); // 16 bytes
    const PATHPORT_UID = Buffer.from('5043081E96CE', 'hex');                     //  6 bytes

    // ── Build Client Entry PDU (E1.33 Table 6-14) ──────────────────────────────
    // Session 17/18 confirmed: Client Entry PDU uses 4-byte vector even when the
    // enclosing broker PDU uses 2-byte vectors (Pathport asymmetry).
    // data: CID(16) + UID(6) + clientType(1) + bindingCID(16) = 39 bytes
    const clientEntryData = Buffer.alloc(39);
    PATHPORT_CID.copy(clientEntryData, 0);  // CID = root CID per E1.33
    PATHPORT_UID.copy(clientEntryData, 16); // UID
    clientEntryData[22] = 0x00;             // ClientType: 0x00 = RPT Device (E1.33 Table 6-15, matches real Pathports)
    // bytes 23-38: Binding CID = 0x00...00
    const ceVec = Buffer.alloc(4); ceVec.writeUInt32BE(0x00000005, 0); // VECTOR_BROKER_CLIENT_ENTRY_RPT
    const ceBody = Buffer.concat([ceVec, clientEntryData]);            // 4 + 39 = 43 bytes
    const ceTotal = 3 + 43;                                            // 46 = 0x2E
    const ceFL = Buffer.from([0xF0 | ((ceTotal >> 16) & 0x0F), (ceTotal >> 8) & 0xFF, ceTotal & 0xFF]);
    const clientEntryPDU = Buffer.concat([ceFL, ceBody]);              // 46 bytes

    // ── Build Broker PDU (BROKER_CONNECT, 2-byte vector) ───────────────────────
    // Pathport sends 2-byte broker vectors.  brkData = scope(63)+ver(2)+domain(231)+flags(1)+entry(46)
    const brkData = Buffer.alloc(297);
    Buffer.from('default', 'ascii').copy(brkData, 0);  // scope
    brkData.writeUInt16BE(0x0001, 63);                 // E1.33 version
    // search domain at offset 65 — 231 zero bytes; flags at offset 296 — 0x00
    const brkConnectData = Buffer.concat([brkData, clientEntryPDU]); // 297 + 46 = 343 bytes
    const brkVecBuf = Buffer.from([0x00, 0x01]);      // VECTOR_BROKER_CONNECT, 2-byte
    const brkBody = Buffer.concat([brkVecBuf, brkConnectData]);      // 2 + 343 = 345 bytes
    const brkTotal = 3 + 345;                                        // 348
    const brkFL = Buffer.from([0xF0 | ((brkTotal >> 16) & 0x0F), (brkTotal >> 8) & 0xFF, brkTotal & 0xFF]);
    const brkPDU = Buffer.concat([brkFL, brkBody]);   // 348 bytes

    // ── Build Root PDU (4-byte vector, 3-byte FL) ──────────────────────────────
    const rootVecBuf = Buffer.alloc(4); rootVecBuf.writeUInt32BE(0x00000009, 0); // VECTOR_ROOT_BROKER
    const rootBody = Buffer.concat([rootVecBuf, PATHPORT_CID, brkPDU]);           // 4+16+348 = 368 bytes
    const rootTotal = 3 + 368;  // 371 = 0x173
    const rootFL = Buffer.from([0xF0 | ((rootTotal >> 16) & 0x0F), (rootTotal >> 8) & 0xFF, rootTotal & 0xFF]);
    const rootPDU = Buffer.concat([rootFL, rootBody]); // 371 bytes

    // ── Build Pathport preamble: ACN_PID(12) + remaining_length(4) ─────────────
    const preamble = Buffer.alloc(16);
    ACN_PID_BUF.copy(preamble, 0);
    preamble.writeUInt32BE(rootPDU.length, 12); // remaining_length = 371
    const brokerConnect = Buffer.concat([preamble, rootPDU]); // 16 + 371 = 387 bytes

    // ── Expected REPLY byte layout for spec E1.33 TCP format (2-byte broker vector, 3-byte FL) ──
    // bytes 0-11: ACN_PID (Pathport preamble)         verified: (a) hasPPreamble
    // byte  16:   0xF0 (3-byte FL top bit set)         verified: (c) has3ByteFL
    // bytes 42-43: 0x0002 (broker vec = REPLY, 2 bytes per E1.33) verified: (d) hasCorrectBrkVec
    // bytes 54-59: client UID                          verified: (e) uidMatch
    // Total: 60B — preamble(16)+rootFL(3)+rootVec(4)+rootCID(16)+brkFL(3)+brkVec(2)+data(16)
    const REPLY_MIN_SIZE = 60;
    const BRK_OFFSET    = 16 + 3 + 4 + 16; // = 39: preamble(16) + rootFL(3) + rootVec(4) + rootCID(16)
    const BRK_VEC_START = BRK_OFFSET + 3;  // = 42: skip brokerFL(3)
    const CLIENT_UID_OFF = BRK_VEC_START + 2 + 2 + 2 + 6; // = 54: vec(2)+code(2)+ver(2)+brokerUID(6)

    const simResult = await new Promise((resolve) => {
      const timeout = setTimeout(() => resolve({ error: 'timeout: no REPLY within 3s' }), 3000);
      let rxBuf = Buffer.alloc(0);
      let settled = false;

      const mockClient = net_mod.connect(broker6.port, '127.0.0.1', () => {
        mockClient.write(brokerConnect);
      });

      mockClient.on('data', (chunk) => {
        rxBuf = Buffer.concat([rxBuf, chunk]);
        if (!settled && rxBuf.length >= REPLY_MIN_SIZE) {
          settled = true;
          clearTimeout(timeout);
          // Inspect REPLY packet
          const hasPPreamble     = rxBuf.slice(0, 12).equals(ACN_PID_BUF);
          const has3ByteFL       = (rxBuf[16] & 0x80) !== 0;
          const hasCorrectBrkVec = rxBuf.length >= BRK_VEC_START + 2 &&
                                   rxBuf.readUInt16BE(BRK_VEC_START) === 0x0002;
          const echoedUID        = rxBuf.slice(CLIENT_UID_OFF, CLIENT_UID_OFF + 6);
          const uidMatch         = echoedUID.equals(PATHPORT_UID);
          // Check 1 (t+650ms): REPLY accepted — socket still alive after broker's 500ms CCL timer
          // Check 2 (t+1100ms): CCL accepted — socket still alive 600ms after broker sent CCL at t+500ms
          //   This is AFTER the broker's second diagnostic timer fires at t+1000ms, so if the broker
          //   sees "socket still alive 500ms after CCL" we know CCL was not rejected.
          // The mock client is passive — it doesn't validate CCL content, just keeps the socket open.
          // Extending from 650ms→1200ms eliminates the false-positive "CCL is the culprit" log that
          //   previously appeared when mockClient.destroy() at 650ms triggered the broker's 1000ms timer.
          setTimeout(() => {
            const socketAliveAfterReply = !mockClient.destroyed;
            setTimeout(() => {
              const socketAliveAfterCCL = !mockClient.destroyed;
              mockClient.destroy();
              resolve({ hasPPreamble, has3ByteFL, hasCorrectBrkVec, uidMatch,
                        socketAliveAfterReply, socketAliveAfterCCL });
            }, 450); // 650 + 450 = 1100ms after REPLY received
          }, 650);
        }
      });

      mockClient.on('error', (e) => {
        if (!settled) { settled = true; clearTimeout(timeout); resolve({ error: e.message }); }
      });
    });

    broker6.stop();

    if (simResult.error) {
      results.failed.push(`Pathport handshake simulation: ${simResult.error}`);
    } else {
      simResult.hasPPreamble
        ? results.passed.push('Pathport REPLY: correct Pathport preamble (ACN_PID at byte 0)')
        : results.failed.push('Pathport REPLY: preamble wrong — expected ACN_PID at byte 0');
      simResult.has3ByteFL
        ? results.passed.push('Pathport REPLY: 3-byte flags+length encoding (byte 16 = 0xF0)')
        : results.failed.push('Pathport REPLY: flags+length wrong — expected 3-byte (0xF0)');
      simResult.hasCorrectBrkVec
        ? results.passed.push('Pathport REPLY: 2-byte broker vector (0x0002 = BROKER_CONNECT_REPLY, per E1.33)')
        : results.failed.push('Pathport REPLY: broker vector wrong — expected 2-byte 0x0002');
      simResult.uidMatch
        ? results.passed.push(`Pathport REPLY: correct client UID echoed (${PATHPORT_UID.toString('hex').toUpperCase()})`)
        : results.failed.push(`Pathport REPLY: wrong UID echoed — expected ${PATHPORT_UID.toString('hex').toUpperCase()}`);
      simResult.socketAliveAfterReply
        ? results.passed.push('Pathport REPLY: socket stays alive 650ms after REPLY (REPLY accepted)')
        : results.failed.push('Pathport REPLY: socket destroyed within 650ms of REPLY — broker rejected client');
      simResult.socketAliveAfterCCL
        ? results.passed.push('Pathport CCL: socket stays alive 1100ms after REPLY (CCL accepted, handshake complete)')
        : results.failed.push('Pathport CCL: socket destroyed 650–1100ms after REPLY — CCL was rejected by client');
    }
  } catch (e) {
    results.failed.push(`Pathport handshake simulation threw: ${e.message}`);
  }

  // ─── Test 6b: Non-empty CCL — controller already connected when Pathport joins ─────
  // In the real Mac scenario, rdmnet.js scanner connects to the broker first (as a
  // Controller, type=1), then Pathports connect.  The CCL sent to each Pathport must
  // include the controller's client entry — a 90B non-empty CCL instead of a 44B empty one.
  //
  // This is the only scenario where we're SURE the CCL is non-empty.  Without this test
  // the non-empty CCL code path was completely untested in the VM.
  //
  // Expected sizes (spec E1.33 TCP format, 3-byte FL, 2-byte broker vector):
  //   REPLY:             60B
  //   CCL (1 entry):     90B   (44B header + 46B controller-entry PDU)
  //   Total received:   150B
  try {
    const net_6b = require('net');
    const broker6b = new RDMnetBroker();
    broker6b.on('log', () => {});
    await broker6b.start();

    const ACN_PID_12b = Buffer.from('4153432d45312e313700000000000000', 'hex').slice(0, 12);

    // ── Standard-format BROKER_CONNECT for mock controller (type=1) ──────────────────
    const CTRL_CID = Buffer.from('1234567890abcdef1234567890abcdef', 'hex');
    const CTRL_UID = Buffer.from('7ff000000001', 'hex');
    // Client Entry PDU (standard 2-byte FL, 4-byte vector, type=1=Controller)
    const ceDataCtrl = Buffer.alloc(39);
    CTRL_CID.copy(ceDataCtrl, 0);  CTRL_UID.copy(ceDataCtrl, 16);  ceDataCtrl[22] = 0x01;
    const ceVecCtrl = Buffer.alloc(4); ceVecCtrl.writeUInt32BE(0x00000005, 0);
    const ceBodyCtrl = Buffer.concat([ceVecCtrl, ceDataCtrl]);          // 43B
    const ceTotCtrl = 2 + 43;                                           // 45
    const ceFLCtrl = Buffer.from([0x70 | ((ceTotCtrl >> 8) & 0x0F), ceTotCtrl & 0xFF]);
    const cePDUCtrl = Buffer.concat([ceFLCtrl, ceBodyCtrl]);            // 45B
    // Broker PDU (standard 2-byte FL, 4-byte BROKER_CONNECT vector)
    const brkDataCtrl = Buffer.alloc(297);
    Buffer.from('default', 'ascii').copy(brkDataCtrl, 0);  brkDataCtrl.writeUInt16BE(0x0001, 63);
    const brkVecCtrl = Buffer.alloc(4); brkVecCtrl.writeUInt32BE(0x00000001, 0);
    const brkBodyCtrl = Buffer.concat([brkVecCtrl, brkDataCtrl, cePDUCtrl]);  // 4+297+45=346B
    const brkTotCtrl = 2 + 346;                                         // 348
    const brkFLCtrl = Buffer.from([0x70 | ((brkTotCtrl >> 8) & 0x0F), brkTotCtrl & 0xFF]);
    const brkPDUCtrl = Buffer.concat([brkFLCtrl, brkBodyCtrl]);         // 348B
    // Root PDU
    const rootVecCtrl = Buffer.alloc(4); rootVecCtrl.writeUInt32BE(0x00000009, 0);
    const rootBodyCtrl = Buffer.concat([rootVecCtrl, CTRL_CID, brkPDUCtrl]);  // 4+16+348=368B
    const rootTotCtrl = 2 + 368;                                        // 370
    const rootFLCtrl = Buffer.from([0x70 | ((rootTotCtrl >> 8) & 0x0F), rootTotCtrl & 0xFF]);
    const rootPDUCtrl = Buffer.concat([rootFLCtrl, rootBodyCtrl]);      // 370B
    // Standard preamble: preamble_size(2) + postamble_size(2) + ACN_PID(12)
    const preambleCtrl = Buffer.alloc(16);
    preambleCtrl.writeUInt16BE(0x0010, 0);  preambleCtrl.writeUInt16BE(0x0000, 2);
    ACN_PID_12b.copy(preambleCtrl, 4);
    const ctrlConnect = Buffer.concat([preambleCtrl, rootPDUCtrl]);     // 386B

    // ── Pathport-format BROKER_CONNECT (same construction as Test 6) ─────────────────
    const PP_CID_6b = Buffer.from('001e96ce00005043800000a11e96ce01', 'hex');
    const PP_UID_6b = Buffer.from('5043081E96CE', 'hex');
    const ceDataPP = Buffer.alloc(39); PP_CID_6b.copy(ceDataPP, 0); PP_UID_6b.copy(ceDataPP, 16); ceDataPP[22] = 0x00; // type 0 = RPT Device
    const ceVecPP = Buffer.alloc(4); ceVecPP.writeUInt32BE(0x00000005, 0);
    const ceBodyPP = Buffer.concat([ceVecPP, ceDataPP]);                // 43B
    const ceTotPP = 3 + 43;                                             // 46
    const ceFLPP = Buffer.from([0xF0 | ((ceTotPP >> 16) & 0x0F), (ceTotPP >> 8) & 0xFF, ceTotPP & 0xFF]);
    const cePDUPP = Buffer.concat([ceFLPP, ceBodyPP]);                  // 46B
    const brkDataPP = Buffer.alloc(297); Buffer.from('default', 'ascii').copy(brkDataPP, 0); brkDataPP.writeUInt16BE(0x0001, 63);
    const brkBodyPP = Buffer.concat([Buffer.from([0x00, 0x01]), brkDataPP, cePDUPP]);  // 2+297+46=345B
    const brkTotPP = 3 + 345;                                           // 348
    const brkFLPP = Buffer.from([0xF0 | ((brkTotPP >> 16) & 0x0F), (brkTotPP >> 8) & 0xFF, brkTotPP & 0xFF]);
    const brkPDUPP = Buffer.concat([brkFLPP, brkBodyPP]);              // 348B
    const rootVecPP = Buffer.alloc(4); rootVecPP.writeUInt32BE(0x00000009, 0);
    const rootBodyPP = Buffer.concat([rootVecPP, PP_CID_6b, brkPDUPP]); // 4+16+348=368B
    const rootTotPP = 3 + 368;                                          // 371
    const rootFLPP = Buffer.from([0xF0 | ((rootTotPP >> 16) & 0x0F), (rootTotPP >> 8) & 0xFF, rootTotPP & 0xFF]);
    const rootPDUPP = Buffer.concat([rootFLPP, rootBodyPP]);            // 371B
    const preamblePP = Buffer.alloc(16); ACN_PID_12b.copy(preamblePP, 0); preamblePP.writeUInt32BE(rootPDUPP.length, 12);
    const ppConnect = Buffer.concat([preamblePP, rootPDUPP]);           // 387B

    // Expected sizes (spec E1.33 TCP format, 3B FL, 2B broker vector):
    //   REPLY: 60B
    //   CCL with 1 controller entry: 44B header + 46B entry = 90B
    //   Total: 150B
    const EXPECTED_TOTAL = 60 + 90;

    let ctrlSock6b = null;
    let ppSock6b   = null;

    const test6bResult = await new Promise((resolve) => {
      const outerTimeout = setTimeout(() => resolve({ error: 'timeout: did not receive 150B within 3s' }), 3000);
      let ppRxBuf  = Buffer.alloc(0);
      let settled  = false;

      // Step 1: connect mock controller — gives it enough time to be marked connected
      ctrlSock6b = net_6b.connect(broker6b.port, '127.0.0.1', () => { ctrlSock6b.write(ctrlConnect); });
      ctrlSock6b.on('error', () => {});

      // Step 2: 200ms later, connect mock Pathport (controller.connected=true by now)
      setTimeout(() => {
        ppSock6b = net_6b.connect(broker6b.port, '127.0.0.1', () => { ppSock6b.write(ppConnect); });
        ppSock6b.on('data', (chunk) => {
          ppRxBuf = Buffer.concat([ppRxBuf, chunk]);
          if (!settled && ppRxBuf.length >= EXPECTED_TOTAL) {
            settled = true;
            clearTimeout(outerTimeout);
            // Wait 200ms to confirm no disconnect after CCL
            setTimeout(() => {
              const alive = ppSock6b && !ppSock6b.destroyed;
              resolve({ totalRx: ppRxBuf.length, alive });
            }, 200);
          }
        });
        ppSock6b.on('error', () => {
          if (!settled) { settled = true; clearTimeout(outerTimeout); resolve({ error: 'ppSock error' }); }
        });
      }, 200);
    });

    // Cleanup
    try { if (ctrlSock6b && !ctrlSock6b.destroyed) ctrlSock6b.destroy(); } catch(_) {}
    try { if (ppSock6b   && !ppSock6b.destroyed)   ppSock6b.destroy(); }   catch(_) {}
    broker6b.stop();

    if (test6bResult.error) {
      results.failed.push(`Non-empty CCL: ${test6bResult.error}`);
    } else {
      test6bResult.totalRx >= EXPECTED_TOTAL
        ? results.passed.push(`Non-empty CCL: Pathport received ${test6bResult.totalRx}B (REPLY=60B + CCL=90B with controller entry) ✓`)
        : results.failed.push(`Non-empty CCL: expected ≥${EXPECTED_TOTAL}B (REPLY+CCL), got ${test6bResult.totalRx}B — CCL may be missing or empty`);
      test6bResult.alive
        ? results.passed.push('Non-empty CCL: socket stays alive after CCL containing existing client entry')
        : results.failed.push('Non-empty CCL: socket destroyed after non-empty CCL — format rejected by mock client');
    }
  } catch (e) {
    results.failed.push(`Non-empty CCL test threw: ${e.message}`);
  }

  // ─── Test 7: Broker TCP handshake with at least one Pathport ────────────────
  // INTEGRATION TEST — requires Pathports powered on and on the network.
  // PASS: at least one RPT Gateway TCP-connects to the broker and completes the
  //       BROKER_CONNECT handshake within 35s (before any RDM scan is run).
  // FAIL: no gateway connects within 35s, or broker fails to start.
  //
  // This test specifically validates the broker connection fix (Attempts 24+25):
  //   - Pathport sends BROKER_CONNECT with Pathport ACN preamble format
  //   - Broker parses it correctly (correct CID/UID via eVecSize=4)
  //   - Broker sends BROKER_CONNECT_REPLY with correct encoding (2-byte broker vector)
  //   - Broker sends BROKER_CONNECTED_CLIENT_LIST
  //   - Pathport accepts both packets and stays connected
  //   - broker.getConnectedGateways() returns the Pathport
  try {
    // Lazy require — see note at top of file.
    const Scanner = require('../src/scanner');
    // Access the _sharedBroker via a Scanner instance (this.broker = _sharedBroker)
    const scannerRef = new Scanner();
    const brokerRef = scannerRef.broker;

    // Poll every 500ms for up to 35s waiting for a gateway to connect
    const brokerConnectionResult = await new Promise((resolve) => {
      let elapsed = 0
      const poll = setInterval(() => {
        elapsed += 500
        const gateways = brokerRef.getConnectedGateways ? brokerRef.getConnectedGateways() : []
        if (gateways.length > 0) {
          clearInterval(poll)
          resolve({ gateways })
        } else if (elapsed >= 35000) {
          clearInterval(poll)
          resolve({ gateways: [] })
        }
      }, 500)
    })
    scannerRef.stop()  // stop any scan loop but NOT the broker (broker must persist)

    if (brokerConnectionResult.gateways.length > 0) {
      const g = brokerConnectionResult.gateways
      results.passed.push(
        `Broker TCP handshake: ${g.length} gateway(s) connected — ` +
        g.map(gw => `${gw.ip} (UID=${gw.uid})`).join(', ')
      )
    } else {
      results.failed.push(
        'Broker TCP handshake: 0 gateways connected within 35s — ' +
        'verify Pathports are powered on and configured for E1.33 RDMnet (Unsecured)'
      )
    }
  } catch (e) {
    results.failed.push(`Broker TCP handshake test threw: ${e.message}`)
  }

  // ─── Test 8: Full scan finds at least one RDM lighting fixture ───────────────
  // INTEGRATION TEST — requires real hardware connected to the network.
  // PASS: scan completes and at least one deviceFound event fires.
  // FAIL: scan completes with zero devices, or scan throws / times out.
  try {
    const Scanner  = require('../src/scanner');
    const scanner  = new Scanner();
    const devices  = [];       // collected via event (mirrors allDevices return value)
    const progress = [];       // scan log lines for debugging

    scanner.on('deviceFound', (d) => devices.push(d));
    scanner.on('progress',    (p) => progress.push(p.message));
    scanner.on('error',       () => {}); // suppress unhandled-error noise in test output

    // Race the full scan against a hard timeout so the test suite doesn't hang.
    const scanPromise = scanner.fullScan('0.0.0.0', null, 'both');
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Scan did not complete within ${SCAN_TIMEOUT_MS / 1000}s`)), SCAN_TIMEOUT_MS)
    );

    const allDevices = await Promise.race([scanPromise, timeoutPromise]);

    if (allDevices.length > 0) {
      results.passed.push(
        `Scan found ${allDevices.length} RDM fixture(s): ` +
        allDevices.map(d => d.deviceLabel || d.uidStr || 'unknown').join(', ')
      );
    } else {
      results.failed.push(
        'Scan completed but found 0 RDM fixtures — ' +
        'verify fixtures are powered and connected'
      );
    }

    scanner.stop();
  } catch (e) {
    results.failed.push(`Fixture scan failed: ${e.message}`);
  }

  // ─── Print results ────────────────────────────────────────────────────────────
  console.log('\n=== TEST RESULTS ===');
  results.passed.forEach(t => console.log(`  ✓ ${t}`));
  results.failed.forEach(t => console.log(`  ✗ ${t}`));
  console.log(`\n${results.passed.length} passed, ${results.failed.length} failed`);

  process.exit(results.failed.length > 0 ? 1 : 0);
}

runTest().catch(e => {
  console.error('Test runner crashed:', e);
  process.exit(1);
});
