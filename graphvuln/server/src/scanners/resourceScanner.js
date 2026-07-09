'use strict';

const path = require('path');

let findingId = 0;
function nextId() {
  findingId += 1;
  return `res_finding_${findingId}`;
}

// Risky file extensions/suffixes that shouldn't ship inside a project bundle.
// Ported from graphvuln_resource_scanner.cpp's extension table.
const RISKY_EXTENSIONS = [
  { ext: '.pem', type: 'EXPOSED_SENSITIVE_DATA', severity: 'CRITICAL', title: 'Private key / certificate file present' },
  { ext: '.key', type: 'EXPOSED_SENSITIVE_DATA', severity: 'CRITICAL', title: 'Raw key file present' },
  { ext: '.env', type: 'EXPOSED_SENSITIVE_DATA', severity: 'HIGH', title: 'Environment file with potential secrets' },
  { ext: '.sqlite', type: 'EXPOSED_SENSITIVE_DATA', severity: 'MEDIUM', title: 'Embedded database file' },
  { ext: '.db', type: 'EXPOSED_SENSITIVE_DATA', severity: 'MEDIUM', title: 'Embedded database file' },
  { ext: '_backup.gd', type: 'EXPOSED_SENSITIVE_DATA', severity: 'LOW', title: 'Backup script artifact' },
];

/**
 * Scans a flat list of {relativePath} file entries (as gathered by the
 * caller walking a project tree) for risky-by-extension files.
 * @param {{relativePath: string}[]} fileList
 */
function scanFileList(fileList) {
  const findings = [];
  for (const entry of fileList) {
    const lower = entry.relativePath.toLowerCase();
    const hit = RISKY_EXTENSIONS.find((r) => lower.endsWith(r.ext));
    if (hit) {
      findings.push({
        id: nextId(),
        resourcePath: entry.relativePath,
        type: hit.type,
        severity: hit.severity,
        title: hit.title,
        description: `A file matching the risky pattern '${hit.ext}' is present in the project bundle. Files like this commonly contain secrets or data that shouldn't ship with a build.`,
        remediation: 'Remove this file from the exported project, or move its contents to a secrets manager / external config not bundled with the build.',
      });
    }
  }
  return findings;
}

module.exports = { scanFileList, RISKY_EXTENSIONS };
