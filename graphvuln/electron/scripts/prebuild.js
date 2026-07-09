'use strict';
const fs = require('fs');
const path = require('path');

function copyDir(src, dest) {
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

const root = path.join(__dirname, '..', '..');
copyDir(path.join(root, 'server', 'src'), path.join(__dirname, '..', 'vendor', 'server-src'));
copyDir(path.join(root, 'client', 'dist'), path.join(__dirname, '..', 'vendor', 'client-dist'));
console.log('Vendored server/src and client/dist into electron/vendor/');
