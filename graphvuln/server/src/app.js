'use strict';

const express = require('express');
const { createHandler } = require('graphql-http/lib/use/express');
const { ruruHTML } = require('ruru/server');
const { scanProject } = require('./projectScanner');
const {
  buildForensicReport, exportSarif, exportCsv, exportMarkdownSummary,
} = require('./reportExporter');
const { runScenario, SIMULATORS } = require('./attackSimulator');
const { schema } = require('./graphqlSchema');

function createApp() {
  const app = express();
  app.use(express.json());

  // Real GraphQL endpoint (graphql-js + graphql-http, spec-compliant).
  // Try e.g.: query { scan(projectDir: "/abs/path") { totalFindings bySeverity { CRITICAL } } }
  app.all('/graphql', createHandler({ schema }));

  // Interactive GraphQL IDE (ruru — a lightweight GraphiQL-style explorer)
  // pointed at the endpoint above, for perito/dev exploration.
  app.get('/graphiql', (req, res) => {
    res.type('html').send(ruruHTML({ endpoint: '/graphql' }));
  });

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', tool: 'GraphVuln', version: '1.0.0' });
  });

  // POST /api/scan { projectDir: string }
  app.post('/api/scan', (req, res) => {
    const { projectDir } = req.body || {};
    if (!projectDir) {
      return res.status(400).json({ error: 'projectDir is required' });
    }
    try {
      const result = scanProject(projectDir);
      const report = buildForensicReport(result.codeFindings, result.resourceFindings);
      res.json({ ...result, report });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // POST /api/export/:format { codeFindings, resourceFindings }
  // format: json | sarif | csv | markdown
  app.post('/api/export/:format', (req, res) => {
    const { codeFindings = [], resourceFindings = [] } = req.body || {};
    const { format } = req.params;

    switch (format) {
      case 'json':
        res.type('application/json').send(JSON.stringify(buildForensicReport(codeFindings, resourceFindings), null, 2));
        break;
      case 'sarif':
        res.type('application/json').send(exportSarif(codeFindings, resourceFindings));
        break;
      case 'csv':
        res.type('text/csv').send(exportCsv(codeFindings, resourceFindings));
        break;
      case 'markdown':
        res.type('text/markdown').send(exportMarkdownSummary(codeFindings, resourceFindings));
        break;
      default:
        res.status(400).json({ error: `Unknown format: ${format}. Use json, sarif, csv, or markdown.` });
    }
  });

  // GET /api/scenarios — list available simulated attack scenarios
  app.get('/api/scenarios', (req, res) => {
    res.json({ scenarios: SIMULATORS.concat(['full_stack_attack']) });
  });

  // POST /api/scenarios/:name { target, payload?, path?, command?, params? }
  // NOTE: always a simulation — see attackSimulator.js. Never executes
  // anything against a real target.
  app.post('/api/scenarios/:name', (req, res) => {
    const result = runScenario(req.params.name, req.body || {});
    res.json(result);
  });

  return app;
}

module.exports = { createApp };
