'use strict';

// GraphVuln attack scenario simulator — Node.js port of the C++
// GraphVulnAttackSimulator. IMPORTANT, same as the original: this produces
// a structured, documentation-shaped *description* of a hypothetical
// attack's impact. It never executes a payload against a real target —
// there is no socket, no shell, no SQL connection involved. `success` is
// always false and `simulationMode` is always true. This is intentional:
// it exists to help a report explain *why* a finding matters, not to
// perform real exploitation.

function baseResult(attackType, target, extra = {}) {
  return {
    attackType,
    target,
    timestamp: new Date().toISOString(),
    success: false, // always false — this is a simulation, not a real exploit
    simulationMode: true,
    ...extra,
  };
}

const SIMULATORS = {
  SQL_INJECTION: (target, payload) =>
    baseResult('SQL_INJECTION', target, {
      severity: 'CRITICAL',
      details: { payload, targetComponent: target },
      impact: { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'MEDIUM', scope: 'DATABASE' },
      narrative: `If ${target} were vulnerable, a payload like the one supplied could allow reading or modifying arbitrary rows.`,
    }),
  XSS: (target, payload) =>
    baseResult('XSS', target, {
      severity: 'HIGH',
      details: { payload, targetComponent: target },
      impact: { confidentiality: 'MEDIUM', integrity: 'MEDIUM', availability: 'LOW', scope: 'CLIENT_SESSION' },
      narrative: `If unsanitized, this payload could execute in another user's session when rendered by ${target}.`,
    }),
  CSRF: (target, params) =>
    baseResult('CSRF', target, {
      severity: 'MEDIUM',
      details: { params, targetComponent: target },
      impact: { confidentiality: 'LOW', integrity: 'HIGH', availability: 'LOW', scope: 'USER_ACTION' },
      narrative: `Without a CSRF token check, ${target} could be triggered by a forged cross-site request.`,
    }),
  PATH_TRAVERSAL: (target, targetPath) =>
    baseResult('PATH_TRAVERSAL', target, {
      severity: 'HIGH',
      details: { path: targetPath, targetComponent: target },
      impact: { confidentiality: 'HIGH', integrity: 'LOW', availability: 'LOW', scope: 'FILESYSTEM' },
      narrative: `A crafted path could escape the intended directory when handled by ${target}.`,
    }),
  COMMAND_INJECTION: (target, command) =>
    baseResult('COMMAND_INJECTION', target, {
      severity: 'CRITICAL',
      details: { command, targetComponent: target },
      impact: { confidentiality: 'HIGH', integrity: 'HIGH', availability: 'HIGH', scope: 'HOST' },
      narrative: `If unvalidated, an attacker-controlled command could run with the privileges of ${target}.`,
    }),
  PRIVILEGE_ESCALATION: (target) =>
    baseResult('PRIVILEGE_ESCALATION', target, {
      severity: 'HIGH',
      details: { targetComponent: target },
      impact: { confidentiality: 'MEDIUM', integrity: 'HIGH', availability: 'LOW', scope: 'AUTHORIZATION' },
      narrative: `Without an authority check, a low-privilege caller might reach privileged logic in ${target}.`,
    }),
  LOGIC_BYPASS: (target) =>
    baseResult('LOGIC_BYPASS', target, {
      severity: 'MEDIUM',
      details: { targetComponent: target },
      impact: { confidentiality: 'LOW', integrity: 'MEDIUM', availability: 'LOW', scope: 'BUSINESS_LOGIC' },
      narrative: `A crafted input could bypass the intended validation branch in ${target}.`,
    }),
};

function runScenario(scenarioName, params = {}) {
  if (scenarioName === 'full_stack_attack') {
    const results = [
      SIMULATORS.SQL_INJECTION(params.target || 'unknown', params.payload || "' OR '1'='1"),
      SIMULATORS.PRIVILEGE_ESCALATION(params.target || 'unknown'),
      SIMULATORS.PATH_TRAVERSAL(params.target || 'unknown', params.path || '../../etc/passwd'),
    ];
    return { scenarioName, simulationMode: true, results };
  }

  const fn = SIMULATORS[scenarioName];
  if (!fn) {
    return { scenarioName, error: `Unknown scenario: ${scenarioName}`, availableScenarios: Object.keys(SIMULATORS).concat(['full_stack_attack']) };
  }
  return { scenarioName, simulationMode: true, result: fn(params.target || 'unknown', params.payload || params.path || params.command || params.params) };
}

module.exports = { runScenario, SIMULATORS: Object.keys(SIMULATORS) };
