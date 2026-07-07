// scripts/make-icon.js
// Renders build/icon.png (1024×1024) — a stylized 5-pin DMX (XLR-5) connector:
// a white ring with five white pins on the app's dark background, transparent
// rounded-square corners. Run with: ./node_modules/.bin/electron scripts/make-icon.js
'use strict'
const { app, BrowserWindow } = require('electron')
const fs = require('fs')
const path = require('path')

const S = 1024

function draw() {
  const S = 1024
  const c = document.createElement('canvas')
  c.width = S; c.height = S
  const x = c.getContext('2d')

  // Rounded-square background (macOS superellipse-ish corner radius)
  const r = 232
  x.fillStyle = '#0E1524'
  x.beginPath()
  x.moveTo(r, 0)
  x.arcTo(S, 0, S, S, r)
  x.arcTo(S, S, 0, S, r)
  x.arcTo(0, S, 0, 0, r)
  x.arcTo(0, 0, S, 0, r)
  x.closePath()
  x.fill()

  const cx = 512, cy = 512

  // Connector shell — white ring
  x.strokeStyle = '#ffffff'
  x.lineWidth = 30
  x.beginPath()
  x.arc(cx, cy, 300, 0, Math.PI * 2)
  x.stroke()

  // Five pins in the classic 5-pin XLR layout: 2 top, 1 centre, 2 bottom
  const off = 118, dropTop = -112, dropBot = 128, pin = 44
  const pins = [
    [cx - off, cy + dropTop],
    [cx + off, cy + dropTop],
    [cx,       cy + 8],
    [cx - off, cy + dropBot],
    [cx + off, cy + dropBot],
  ]
  x.fillStyle = '#ffffff'
  for (const [px, py] of pins) {
    x.beginPath()
    x.arc(px, py, pin, 0, Math.PI * 2)
    x.fill()
  }

  return c.toDataURL('image/png')
}

app.disableHardwareAcceleration()
app.whenReady().then(async () => {
  const win = new BrowserWindow({
    width: S, height: S, show: false, frame: false, transparent: true,
    webPreferences: { offscreen: false },
  })
  const html = `<!doctype html><html><head><meta charset="utf-8">
    <style>html,body{margin:0;padding:0;background:transparent;width:${S}px;height:${S}px}</style>
    </head><body></body></html>`
  await win.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html))
  const dataUrl = await win.webContents.executeJavaScript(`(${draw.toString()})()`)
  const png = Buffer.from(dataUrl.split(',')[1], 'base64')
  fs.mkdirSync(path.join(__dirname, '..', 'build'), { recursive: true })
  fs.writeFileSync(path.join(__dirname, '..', 'build', 'icon.png'), png)
  console.log('wrote build/icon.png', png.length, 'bytes')
  app.quit()
})
