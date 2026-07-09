'use strict';
const { app, BrowserWindow } = require('electron');
const path = require('path');
const { createApp } = require('../../server/src/app');

const API_PORT = 4123;
const CLIENT_DIST = path.join(__dirname, '..', '..', 'client', 'dist', 'index.html');
const FIXTURE_DIR = path.join(__dirname, '..', '..', 'server', 'test-fixtures');

app.whenReady().then(async () => {
  await new Promise((resolve) => createApp().listen(API_PORT, resolve));

  const win = new BrowserWindow({
    width: 1280, height: 900, backgroundColor: '#14181c',
    webPreferences: { contextIsolation: true, nodeIntegration: false },
  });
  win.loadFile(CLIENT_DIST);

  win.webContents.on('did-finish-load', async () => {
    // Simulate a real user: type the project path, click Scan, wait for
    // the fetch to resolve, then click the first finding to open detail.
    await win.webContents.executeJavaScript(`
      (function() {
        const input = document.querySelector('.project-input');
        const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
        setter.call(input, ${JSON.stringify(FIXTURE_DIR)});
        input.dispatchEvent(new Event('input', { bubbles: true }));
        document.querySelector('.scan-button').click();
      })();
    `);
    await new Promise((r) => setTimeout(r, 1500));
    await win.webContents.executeJavaScript(`
      (function() {
        const row = document.querySelector('.findings-table tbody tr');
        if (row) row.click();
      })();
    `);
    await new Promise((r) => setTimeout(r, 500));
    await win.webContents.capturePage().then((img) => {
      require('fs').writeFileSync('/tmp/shot_scan_result.png', img.toPNG());
      app.quit();
    });
  });
});
