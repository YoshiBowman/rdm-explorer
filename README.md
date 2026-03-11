# RDM Explorer

Discover, inspect, and control RDM-enabled lighting fixtures on Art-Net networks.
Runs as a cross-platform desktop app on Windows, macOS, and Linux.

---

## What it does

- Broadcasts ArtPoll to find Art-Net nodes (including Pathway Pathport)
- Runs RDM discovery (DISC_UNIQUE_BRANCH binary tree) through those nodes
- Reads fixture info: manufacturer, model, DMX address, personality, footprint, software version
- Lets you set DMX start address, device label, and trigger identify from the UI
- Includes a **Demo mode** so you can explore the interface without any hardware

---

## Requirements

- [Node.js](https://nodejs.org) v18 or later
- npm (included with Node.js)
- An Art-Net network with RDM-capable nodes (Pathway Pathport, etc.)
- The computer running RDM Explorer must be on the same subnet as the Art-Net nodes

---

## Quick start (run from source)

```bash
# 1. Install dependencies
npm install

# 2. Launch the app
npm start
```

On first launch, select the network interface connected to your Art-Net network from the dropdown, then click **Scan Network**.

No hardware? Click **Demo** to load sample fixtures and explore the UI.

---

## Building a distributable installer

```bash
# Build for your current platform
npm run build

# Build for a specific platform (run on that platform, or use CI)
npm run build:win      # Windows NSIS installer → dist/
npm run build:mac      # macOS .dmg → dist/
npm run build:linux    # Linux AppImage → dist/
```

Installers appear in the `dist/` folder. The Windows build produces a standard setup wizard; the macOS build produces a .dmg; Linux produces an AppImage that runs without installation.

---

## Project structure

```
rdm-explorer/
├── main.js          Electron main process — window, IPC handlers
├── preload.js       Sandboxed bridge between main and renderer
├── src/
│   ├── artnet.js    Art-Net protocol (ArtPoll, ArtRdm)
│   ├── rdm.js       RDM protocol (packet building, parsing, PIDs)
│   └── scanner.js   Discovery coordinator (nodes → UIDs → device info)
└── renderer/
    ├── index.html   App UI
    ├── styles.css   Dark-themed styles
    └── app.js       UI logic and state
```

---

## How it works

1. **Node discovery** — ArtPoll is broadcast on UDP port 6454. Art-Net nodes reply with their IP, name, and universe configuration.
2. **RDM discovery** — For each node, Art-RDM packets are sent using the binary tree (DISC_UNIQUE_BRANCH) algorithm to enumerate all device UIDs.
3. **Device info** — For each UID, RDM GET requests fetch DEVICE_INFO, MANUFACTURER_LABEL, DEVICE_MODEL_DESCRIPTION, DEVICE_LABEL, SOFTWARE_VERSION_LABEL, and DMX_PERSONALITY_DESCRIPTION.
4. **Control** — SET commands handle DMX start address changes, device labels, and identify.

The source UID used by this controller is `7FF0:00000001` (prototype manufacturer range).

---

## Compatibility

Tested with Pathway Pathport nodes. Should work with any Art-Net node that supports Art-RDM (OpCode 0x8002) and acts as an RDM proxy. sACN sources are visible on the network but RDM is an Art-Net feature and requires Art-Net nodes.

---

## Roadmap

- [ ] Sensor readback (temperature, voltage, etc.)
- [ ] Lamp hours and power cycle counters
- [ ] Pan/tilt invert controls
- [ ] Personality switching
- [ ] Export device list to CSV / PDF
- [ ] sACN source browser (non-RDM)
- [ ] Auto-rescan on network change
- [ ] Dark / light theme toggle

---

## License

MIT — free to use, modify, and distribute.
