'use strict';

const { cweForType } = require('./cweCatalog');

const SEVERITY_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
function severityRank(sev) {
  return SEVERITY_RANK[sev] ?? 4;
}
function severityToSarifLevel(sev) {
  if (sev === 'CRITICAL' || sev === 'HIGH') return 'error';
  if (sev === 'MEDIUM') return 'warning';
  return 'note';
}

function attachCwe(finding) {
  const cwe = cweForType(finding.type);
  return cwe ? { ...finding, cwe } : { ...finding };
}

/**
 * Builds a complete JSON-serializable forensic report.
 */
function buildForensicReport(codeFindings, resourceFindings, securityScore = null) {
  const allFindings = [
    ...codeFindings.map((f) => attachCwe({ ...f, category: 'code' })),
    ...resourceFindings.map((f) => attachCwe({ ...f, category: 'resource' })),
  ].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of allFindings) {
    if (counts[f.severity] !== undefined) counts[f.severity] += 1;
  }

  return {
    generatedAt: new Date().toISOString(),
    tool: { name: 'GraphVuln', version: '1.0.0' },
    summary: {
      totalFindings: allFindings.length,
      bySeverity: counts,
    },
    securityScore: securityScore || undefined,
    findings: allFindings,
  };
}

function exportJson(report) {
  return JSON.stringify(report, null, 2);
}

/**
 * Builds a SARIF 2.1.0 log from raw scanner output.
 */
function buildSarif(codeFindings, resourceFindings) {
  const allFindings = [...codeFindings, ...resourceFindings];
  const seenRules = new Map();
  const rules = [];
  const results = [];

  for (const f of allFindings) {
    if (!seenRules.has(f.type)) {
      const cwe = cweForType(f.type);
      const rule = {
        id: f.type,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        properties: {},
      };
      if (cwe) {
        rule.properties.tags = [cwe.id, 'security'];
        rule.helpUri = cwe.url;
      }
      rules.push(rule);
      seenRules.set(f.type, true);
    }

    const location = f.filePath || f.resourcePath || 'unknown';
    const region = f.lineNumber ? { startLine: f.lineNumber } : undefined;

    results.push({
      ruleId: f.type,
      level: severityToSarifLevel(f.severity),
      message: { text: f.description },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: location },
            ...(region ? { region } : {}),
          },
        },
      ],
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'GraphVuln',
            informationUri: 'https://github.com/graphvuln/graphvuln', // placeholder — update to your project's real URL
            version: '1.0.0',
            rules,
          },
        },
        results,
      },
    ],
  };
}

function exportSarif(codeFindings, resourceFindings) {
  return JSON.stringify(buildSarif(codeFindings, resourceFindings), null, 2);
}

function csvEscape(field) {
  const s = String(field ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function exportCsv(codeFindings, resourceFindings) {
  const report = buildForensicReport(codeFindings, resourceFindings, null);
  const header = 'category,type,cwe_id,cwe_name,severity,title,location,line,description,remediation';
  const rows = report.findings.map((f) => {
    const location = f.filePath || f.resourcePath || '';
    const line = f.lineNumber || '';
    const cwe = f.cwe || {};
    return [
      f.category, f.type, cwe.id || '', cwe.name || '', f.severity, f.title,
      location, line, f.description, f.remediation,
    ].map(csvEscape).join(',');
  });
  return [header, ...rows].join('\n') + '\n';
}

function exportMarkdownSummary(codeFindings, resourceFindings, securityScore = null) {
  const report = buildForensicReport(codeFindings, resourceFindings, securityScore);
  const icons = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵' };
  let md = `# GraphVuln Forensic Report\n\n`;
  md += `Generated: ${report.generatedAt}\n\n`;
  md += `## Summary\n\n`;
  md += `Total findings: **${report.summary.totalFindings}**\n\n`;
  md += `| Severity | Count |\n|---|---|\n`;
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
    md += `| ${icons[sev]} ${sev} | ${report.summary.bySeverity[sev] || 0} |\n`;
  }
  md += `\n### Top findings\n\n`;
  const MAX_SHOWN = 25;
  report.findings.slice(0, MAX_SHOWN).forEach((f) => {
    const loc = (f.filePath || f.resourcePath || '') + (f.lineNumber ? `:${f.lineNumber}` : '');
    const cweTag = f.cwe ? ` \`${f.cwe.id}\`` : '';
    md += `- ${icons[f.severity] || ''} **${f.title}** — \`${loc}\` — ${f.severity}${cweTag}\n`;
  });
  if (report.findings.length > MAX_SHOWN) {
    md += `\n_...and ${report.findings.length - MAX_SHOWN} more._\n`;
  }
  return md;
}

module.exports = {
  buildForensicReport,
  exportJson,
  buildSarif,
  exportSarif,
  exportCsv,
  exportMarkdownSummary,
};
