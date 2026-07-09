'use strict';

const fs = require('fs');
const path = require('path');
const { scanSource } = require('./scanners/gdscriptScanner');
const { scanFileList } = require('./scanners/resourceScanner');

const IGNORED_DIRS = new Set(['.git', '.godot', 'node_modules', '.import']);

function walk(dir, rootDir, out = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (IGNORED_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, rootDir, out);
    } else if (entry.isFile()) {
      out.push({ absolutePath: full, relativePath: path.relative(rootDir, full).split(path.sep).join('/') });
    }
  }
  return out;
}

/**
 * Scans an entire project directory: GDScript static analysis on every
 * .gd file, plus a risky-extension pass over the full file list.
 * @param {string} projectDir - absolute path to the project root.
 */
function scanProject(projectDir) {
  if (!fs.existsSync(projectDir) || !fs.statSync(projectDir).isDirectory()) {
    throw new Error(`Not a directory: ${projectDir}`);
  }

  const files = walk(projectDir, projectDir);
  const gdFiles = files.filter((f) => f.relativePath.endsWith('.gd'));

  let codeFindings = [];
  for (const f of gdFiles) {
    const src = fs.readFileSync(f.absolutePath, 'utf8');
    codeFindings = codeFindings.concat(scanSource(`res://${f.relativePath}`, src));
  }

  const resourceFindings = scanFileList(files);

  return {
    projectDir,
    filesScanned: files.length,
    gdFilesScanned: gdFiles.length,
    codeFindings,
    resourceFindings,
  };
}

module.exports = { scanProject, walk };
