'use strict';

// Maps each internal GraphVuln vulnerability type to its corresponding entry
// in the CWE (Common Weakness Enumeration), the industry-standard weakness
// taxonomy maintained by MITRE. Ported 1:1 from the original C++ module
// (graphvuln_report_exporter.cpp::_cwe_for_type).
const CWE_TABLE = {
  HARDCODED_SECRET: { id: 'CWE-798', name: 'Use of Hard-coded Credentials' },
  INSECURE_RANDOM: { id: 'CWE-330', name: 'Use of Insufficiently Random Values' },
  LOGIC_BYPASS: {
    id: 'CWE-95',
    name: "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
  },
  WEAK_CRYPTOGRAPHY: { id: 'CWE-327', name: 'Use of a Broken or Risky Cryptographic Algorithm' },
  EXPOSED_SENSITIVE_DATA: {
    id: 'CWE-200',
    name: 'Exposure of Sensitive Information to an Unauthorized Actor',
  },
  SQL_INJECTION: {
    id: 'CWE-89',
    name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  },
  PATH_TRAVERSAL: {
    id: 'CWE-22',
    name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
  },
  COMMAND_INJECTION: {
    id: 'CWE-78',
    name: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  },
  INSECURE_DESERIALIZATION: { id: 'CWE-502', name: 'Deserialization of Untrusted Data' },
  PRIVILEGE_ESCALATION: { id: 'CWE-269', name: 'Improper Privilege Management' },
  TIMING_UNSAFE_COMPARISON: { id: 'CWE-208', name: 'Observable Timing Discrepancy' },
  INSECURE_CORS_WILDCARD: {
    id: 'CWE-942',
    name: 'Permissive Cross-domain Policy with Untrusted Domains',
  },
  STACK_TRACE_EXPOSURE: {
    id: 'CWE-209',
    name: 'Generation of Error Message Containing Sensitive Information',
  },
  OPEN_REDIRECT: { id: 'CWE-601', name: "URL Redirection to Untrusted Site ('Open Redirect')" },
  GRAPHQL_INTROSPECTION_ENABLED: {
    id: 'CWE-200',
    name: 'Exposure of Sensitive Information to an Unauthorized Actor',
  },
  INSECURE_SIGNAL: {
    id: 'CWE-200',
    name: 'Exposure of Sensitive Information to an Unauthorized Actor',
  },
};

function cweForType(vulnType) {
  const entry = CWE_TABLE[vulnType];
  if (!entry) return null;
  return {
    id: entry.id,
    name: entry.name,
    url: `https://cwe.mitre.org/data/definitions/${entry.id.replace('CWE-', '')}.html`,
  };
}

module.exports = { CWE_TABLE, cweForType };
