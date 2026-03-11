# RDM Explorer

Discover, inspect, and control RDM-enabled lighting fixtures on Art-Net and sACN networks. Runs as a desktop app on macOS, Windows, and Linux.

---

## Features

- **Dual protocol scanning** — discovers Art-Net nodes and sACN sources simultaneously
- **Protocol toggle** — scan Art-Net only, sACN only, or both at once
- **RDM device discovery** — binary-tree RDM enumeration over Art-Net (Art-RDM)
- **Device details** — manufacturer, model, DMX address, footprint, personality, software version
- **Live control** — set DMX start address, device label, and trigger identify
- **Filter & sort** — search by name, UID, address, or category
- **Demo mode** — explore the UI with realistic fixture data, no hardware needed
- **Auto update check** — notifies you when a new release is available

---

## Installation (macOS DMG)

1. Go to the [Releases page](https://github.com/YoshiBowman/rdm-explorer/releases)
2. Download `RDM Explorer-x.x.x-arm64.dmg` (Apple Silicon) or the x64 build for Intel Macs
3. Open the DMG and drag **RDM Explorer** to your Applications folder

### "App is Damaged" Warning

Because RDM Explorer is not yet signed with an Apple Developer certificate, macOS will block it on first launch. To fix this, open Terminal and run:

```bash
sudo xattr -rd com.apple.quarantine "/Applications/RDM Explorer.app"
```

Then open the app normally. If that still doesn't work, temporarily disable Gatekeeper:

```bash
sudo spctl --master-disable
```

Re-enable Gatekeeper after testing:

```bash
sudo spctl --master-enable
```

---

## Building from Source

### Prerequisites

- [Node.js](https://nodejs.org) v18 or later (includes npm)
- Xcode Command Line Tools — `xcode-select --install`
- Or install both via [Homebrew](https://brew.sh): `brew install node`

### Steps

```bash
git clone https://github.com/YoshiBowman/rdm-explorer.git
cd rdm-explorer
npm install
npm start             # Run in development mode
npm run build:mac     # Build macOS DMG → dist/
npm run build:win     # Build Windows installer → dist/
npm run build:linux   # Build Linux AppImage → dist/
```

---

## Network Requirements

- Art-Net: UDP port **6454** must be open (broadcast)
- sACN: UDP port **5568** must be open (multicast)
- Your computer must be on the same network subnet as your nodes
- RDM control requires an Art-Net gateway that supports Art-RDM (most Pathport, Luminex, and ETC gateways do)

---

## Protocol Support

| Protocol | Discovery | RDM Control |
|----------|-----------|-------------|
| Art-Net (ArtPoll / Art-RDM) | ✓ | ✓ |
| sACN E1.31 (source detection) | ✓ | — |
| sACN E1.33 / RDMnet | Planned | Planned |

sACN sources are discovered passively via multicast listening. RDM control currently requires an Art-Net gateway. Full E1.33 RDMnet (RDM directly over sACN) is planned for a future release.

---

## Project Structure

```
rdm-explorer/
├── main.js          Electron main process — window, IPC, update checker
├── preload.js       Sandboxed bridge between main and renderer
├── src/
│   ├── artnet.js    Art-Net protocol (ArtPoll, Art-RDM)
│   ├── sacn.js      sACN E1.31 protocol (source & universe discovery)
│   ├── rdm.js       RDM protocol (packet building, parsing, PIDs)
│   └── scanner.js   Discovery coordinator (nodes → UIDs → device info)
└── renderer/
    ├── index.html   App UI
    ├── styles.css   Dark-themed styles
    └── app.js       UI logic and state
```

---

## How It Works

1. **Art-Net node discovery** — ArtPoll is broadcast on UDP 6454. Nodes reply with their IP, name, and universe configuration.
2. **sACN source discovery** — The app joins E1.31 multicast groups and listens for Universe Discovery packets and data frames to detect active sources.
3. **RDM discovery** — For each Art-Net node, Art-RDM packets run the binary tree (DISC_UNIQUE_BRANCH) algorithm to enumerate all device UIDs.
4. **Device info** — For each UID, RDM GET requests fetch manufacturer, model, DMX address, personality, footprint, and software version.
5. **Control** — RDM SET commands handle DMX start address changes, device labels, and identify.

The source UID used by this controller is `7FF0:00000001` (prototype manufacturer range).

---

## Roadmap

- [ ] Full E1.33 RDMnet support (RDM directly over sACN)
- [ ] Sensor readback (temperature, voltage, etc.)
- [ ] Lamp hours and power cycle counters
- [ ] Personality switching
- [ ] Pan/tilt invert controls
- [ ] Export device list to CSV / PDF
- [ ] Auto-rescan on network change

---

## License

MIT — free to use, modify, and distribute.
