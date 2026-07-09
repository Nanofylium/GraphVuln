'use strict';

const { app, BrowserWindow } = require('electron');
const fs = require('fs');
const path = require('path');

const API_PORT = process.env.GRAPHVULN_API_PORT || 4123;

// In a packaged build, everything the app needs was vendored into
// electron/vendor/ by scripts/prebuild.js and bundled into app.asar. In
// dev, that vendor copy may be stale or absent, so fall back to the real
// source directories one level up.
const VENDOR_SERVER = path.join(__dirname, 'vendor', 'server-src', 'app.js');
const VENDOR_CLIENT = path.join(__dirname, 'vendor', 'client-dist', 'index.html');
const SERVER_APP_PATH = fs.existsSync(VENDOR_SERVER) ? VENDOR_SERVER : path.join(__dirname, '..', 'server', 'src', 'app.js');
const CLIENT_DIST = fs.existsSync(VENDOR_CLIENT) ? VENDOR_CLIENT : path.join(__dirname, '..', 'client', 'dist', 'index.html');

const { createApp } = require(SERVER_APP_PATH);

let mainWindow;

function startApiServer() {
  return new Promise((resolve) => {
    const apiApp = createApp();
    const server = apiApp.listen(API_PORT, () => resolve(server));
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 860,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#14181c',
    title: 'GraphVuln',
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(CLIENT_DIST);
}

app.whenReady().then(async () => {
  await startApiServer();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
