'use strict';

// GraphVuln GDScript static analysis scanner — Node.js port of
// graphvuln_gdscript_scanner.cpp. Same 16 regex-heuristic passes, same
// finding shape, so downstream (report exporter, CWE mapping) needs no
// changes to consume it.

let findingId = 0;
function nextId() {
  findingId += 1;
  return `finding_${findingId}`;
}

function addFinding(findings, path, lineNumber, lineText, type, severity, title, description, remediation) {
  findings.push({
    id: nextId(),
    filePath: path,
    lineNumber,
    lineText: lineText.trim(),
    type,
    severity, // CRITICAL | HIGH | MEDIUM | LOW
    title,
    description,
    remediation,
  });
}

function isCommentLine(line) {
  return line.trim().startsWith('#');
}

// Pass 1: hardcoded secrets — API keys, passwords, tokens assigned as
// string literals directly in source.
function scanHardcodedSecrets(path, lines, findings) {
  const re = /\b(api_key|apikey|secret|password|passwd|token|access_key|private_key)\s*[:=]\s*["'][^"']{4,}["']/i;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (re.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'HARDCODED_SECRET', 'HIGH',
        'Hardcoded secret / credential in source',
        'A credential-looking value (API key, password, token) is assigned as a string literal directly in source, so it ships with every build and is visible to anyone with the source or the compiled PCK.',
        'Move secrets to environment variables, a secrets manager, or an encrypted config loaded at runtime — never commit them to source.'
      );
    }
  });
}

// Pass 2: insecure randomness — randi()/randf() used in a security-looking
// context (token/session/password generation).
function scanInsecureRandom(path, lines, findings) {
  const ctxRe = /\b(token|session|password|otp|nonce|salt|csrf)\b/i;
  const randRe = /\b(randi|randf|rand_range)\s*\(/;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (ctxRe.test(line) && randRe.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'INSECURE_RANDOM', 'MEDIUM',
        'Non-cryptographic RNG used for a security-sensitive value',
        "Godot's randi()/randf() family is not a cryptographically secure RNG. Using it for tokens, sessions, or nonces makes those values statistically predictable.",
        'Use a CSPRNG source (e.g. an OS-level secure random API) for anything security-sensitive.'
      );
    }
  });
}

// Pass 3: dangerous eval — Expression class evaluating a string built from
// concatenation (i.e., not a fixed literal), which is eval-injection-shaped.
// Anchored specifically to the Expression class (via a nearby "Expression"
// token) so it doesn't collide with unrelated .execute()/.parse() calls
// like OS.execute() or a database driver's .execute().
function scanDangerousEval(path, lines, findings) {
  const re = /Expression\s*\(\s*\)|Expression[\s\S]{0,80}\.(parse|execute)\s*\(.*\+/;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    const windowText = lines.slice(Math.max(0, i - 2), i + 1).join('\n');
    if (/\.(parse|execute)\s*\(.*\+/.test(line) && /\bExpression\b/.test(windowText)) {
      addFinding(
        findings, path, i + 1, line, 'LOGIC_BYPASS', 'HIGH',
        'Dynamic expression evaluation of untrusted input',
        "Godot's Expression class is evaluating a string assembled via concatenation. If any part comes from user input, this is equivalent to eval() injection.",
        'Never build expressions from untrusted input. If dynamic evaluation is required, validate against a strict allow-list.'
      );
    }
  });
}

// Pass 4: unsafe networking — HTTPClient/HTTPRequest created without TLS
// verification, or a raw ws:// / http:// (not https/wss) endpoint.
function scanUnsafeNetworking(path, lines, findings) {
  const tlsSkip = /verify_host\s*=\s*false|TLSOptions\.client_unsafe|set_tls_options\s*\(\s*null/i;
  const plainUrl = /["'](http|ws):\/\/(?!localhost|127\.0\.0\.1)/i;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (tlsSkip.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'WEAK_CRYPTOGRAPHY', 'HIGH',
        'TLS certificate verification disabled',
        'Certificate verification is explicitly disabled, making the connection vulnerable to man-in-the-middle interception.',
        'Never disable certificate verification outside of local dev; use a proper CA bundle in production.'
      );
    } else if (plainUrl.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'EXPOSED_SENSITIVE_DATA', 'MEDIUM',
        'Unencrypted network endpoint',
        'A plain http:// or ws:// endpoint is used against a non-local host. Traffic (including any credentials) travels unencrypted.',
        'Use https:// / wss:// for any endpoint that is not strictly local development.'
      );
    }
  });
}

// Pass 5: SQL injection — a SQL-looking string built by concatenation and
// passed into a query-execution call.
function scanSqlInjection(path, lines, findings) {
  const sqlRe = /\b(SELECT|INSERT|UPDATE|DELETE)\b.*\+/i;
  // Deliberately excludes a bare ".execute(" — that alone is ambiguous
  // with unrelated APIs like OS.execute() and produced false positives.
  const execRe = /\.(query|query_with_bindings)\s*\(/;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (sqlRe.test(line) || (execRe.test(line) && line.includes('+'))) {
      addFinding(
        findings, path, i + 1, line, 'SQL_INJECTION', 'CRITICAL',
        'SQL query built by string concatenation',
        'A SQL statement is assembled via string concatenation rather than parameter binding. If any concatenated part comes from user input, this is a classic SQL injection.',
        'Use parameterized queries / prepared statements exclusively; never interpolate values into SQL text.'
      );
    }
  });
}

// Pass 6: path traversal — file paths built by concatenating a variable
// into a path passed to FileAccess/DirAccess.
function scanPathTraversal(path, lines, findings) {
  const re = /(FileAccess|DirAccess)\.(open|open_encrypted|make_dir)\s*\([^)]*\+/;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (re.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'PATH_TRAVERSAL', 'HIGH',
        'File path built from concatenated, unvalidated input',
        "A file path passed to FileAccess/DirAccess is built by concatenating a variable. If that variable is user-controlled and contains '../', it can escape the intended directory.",
        "Validate and normalize any user-controlled path component, and reject '..' segments before use."
      );
    }
  });
}

// Pass 7: command injection — OS.execute() with a command string built by
// concatenation.
function scanCommandInjection(path, lines, findings) {
  const re = /OS\.execute\s*\([^)]*\+/;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (re.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'COMMAND_INJECTION', 'CRITICAL',
        'OS command built from concatenated input',
        'OS.execute() is called with a command/argument string assembled via concatenation. If any part is user-controlled, an attacker can inject arbitrary shell arguments.',
        'Pass arguments as a separate array (never a single concatenated string), and validate/allow-list any user-controlled component.'
      );
    }
  });
}

// Pass 8: weak cryptography — MD5/SHA1 used in what looks like a
// security-sensitive context (password/signature/token hashing).
function scanWeakCryptography(path, lines, findings) {
  const re = /\b(md5|sha1)\b/i;
  const ctxRe = /\b(password|passwd|signature|token|hmac)\b/i;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (re.test(line) && ctxRe.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'WEAK_CRYPTOGRAPHY', 'MEDIUM',
        'Weak hash algorithm used for a security-sensitive value',
        'MD5/SHA-1 are cryptographically broken for security purposes (collision-prone) and unsuitable for password hashing, signatures, or token generation.',
        'Use a modern password-hashing function (Argon2/bcrypt/scrypt) for passwords, and SHA-256+ for general hashing.'
      );
    }
  });
}

// Pass 9: sensitive data logging — print()/push_error() including a
// variable that looks like a credential.
function scanSensitiveLogging(path, lines, findings) {
  const logRe = /\b(print|push_error|push_warning|print_debug)\s*\(/;
  const ctxRe = /\b(password|passwd|token|secret|api_key|credit_card|ssn)\b/i;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (logRe.test(line) && ctxRe.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'EXPOSED_SENSITIVE_DATA', 'MEDIUM',
        'Sensitive value written to logs',
        'A log statement appears to include a credential or otherwise sensitive value by name. Logs are often less protected than the data they describe and can leak to crash reports, log aggregators, or console output.',
        'Redact or omit sensitive values from log output; log identifiers/hashes instead of raw secrets.'
      );
    }
  });
}

// Pass 10: insecure deserialization — bytes_to_var()/str_to_var() called on
// data from an external/untrusted source (network, file) without validation.
function scanInsecureDeserialization(path, lines, findings) {
  const re = /\b(bytes_to_var|str_to_var)\s*\(/;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (re.test(line)) {
      const allowObjects = /allow_objects\s*[:=]\s*true/i.test(line);
      addFinding(
        findings, path, i + 1, line, 'INSECURE_DESERIALIZATION',
        allowObjects ? 'CRITICAL' : 'MEDIUM',
        'Untrusted data deserialized',
        allowObjects
          ? 'bytes_to_var/str_to_var is called with allow_objects=true, which can instantiate arbitrary Godot Object types from the payload — a classic insecure-deserialization RCE pattern if the data is attacker-controlled.'
          : 'bytes_to_var/str_to_var is used to deserialize data; confirm the source is trusted, since deserializing attacker-controlled data is a common exploitation vector.',
        'Never deserialize untrusted data with allow_objects=true. Prefer a schema-validated format (typed JSON/dictionaries) for anything crossing a trust boundary.'
      );
    }
  });
}

// Pass 11: RPC exposure — an @rpc-annotated function with no visible
// authority/permission check nearby, callable by any connected peer.
function scanRpcExposure(path, lines, findings) {
  const rpcRe = /^\s*@rpc\s*\(/;
  lines.forEach((line, i) => {
    if (rpcRe.test(line)) {
      const nextFew = lines.slice(i, i + 4).join('\n');
      const hasCheck = /(is_multiplayer_authority|get_multiplayer_authority|multiplayer\.get_remote_sender_id)/.test(nextFew);
      if (!hasCheck) {
        addFinding(
          findings, path, i + 1, line, 'PRIVILEGE_ESCALATION', 'HIGH',
          'RPC endpoint with no visible authority check',
          'An @rpc function is exposed to remote peers with no nearby authority/sender check. Any connected peer may be able to invoke privileged logic.',
          'Validate multiplayer authority (or the sender ID) at the top of every @rpc handler before performing privileged actions.'
        );
      }
    }
  });
}

// Pass 12: timing-unsafe comparison — secrets/tokens/passwords compared
// with a direct == instead of a constant-time comparison.
function scanTimingUnsafeComparison(path, lines, findings) {
  const ctxRe = /\b(token|password|passwd|pwd|secret|api[_-]?key|signature|hmac|csrf)\b/i;
  const cmpRe = /\w+\s*==\s*\w+|\w+\s*!=\s*\w+/;
  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('#')) return;
    if (!trimmed.startsWith('if ') && !trimmed.includes(' if ')) return;
    if (ctxRe.test(line) && cmpRe.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'TIMING_UNSAFE_COMPARISON', 'MEDIUM',
        'Non-constant-time comparison of a secret value',
        "A token/password/secret appears to be compared with '==' or '!=', which short-circuits on the first mismatched byte, potentially leaking timing information.",
        'Use a constant-time comparison for any secret value instead of the built-in equality operator.'
      );
    }
  });
}

// Pass 13: insecure CORS — Access-Control-Allow-Origin: *
function scanInsecureCors(path, lines, findings) {
  const re = /Access-Control-Allow-Origin[^\n]*["']\*["']/i;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (re.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'INSECURE_CORS_WILDCARD', 'MEDIUM',
        'Wildcard CORS origin allows any site to read responses',
        "Access-Control-Allow-Origin is set to '*'. If the endpoint returns user-scoped data, any third-party site can read the response cross-origin.",
        "Reflect a specific, validated allow-list of origins instead of '*', and never combine a wildcard origin with credentials."
      );
    }
  });
}

// Pass 14: stack trace / internal error exposure sent back to a client.
function scanStackTraceExposure(path, lines, findings) {
  const stackRe = /get_stack\s*\(\s*\)|error_string\s*\(/;
  const sendRe = /\b(response|reply|send_response|respond|send_text|send_json)\b/i;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (stackRe.test(line) && sendRe.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'STACK_TRACE_EXPOSURE', 'MEDIUM',
        'Internal error detail sent back to the client',
        'A stack trace or raw error string appears alongside a response/reply call, suggesting internal implementation details may be sent to callers.',
        'Log full error detail server-side only; return a generic error message and an opaque request ID to the client.'
      );
    }
  });
}

// Pass 15: open redirect — redirect target built by concatenation.
function scanOpenRedirect(path, lines, findings) {
  const re = /\b(location|redirect_url|redirect_uri|redirect_to)\b\s*[:=]\s*["'][^"']*["']\s*\+\s*\w+/i;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (re.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'OPEN_REDIRECT', 'MEDIUM',
        'Possible open redirect via unvalidated target URL',
        'A redirect target is built by concatenating a variable into a URL/Location value. If user-controlled, an attacker can redirect victims to an arbitrary external site.',
        'Validate the redirect target against an allow-list of known paths/domains before using it.'
      );
    }
  });
}

// Pass 16: GraphQL introspection left enabled.
function scanGraphqlIntrospectionEnabled(path, lines, findings) {
  const re = /(enable_introspection|introspection[_-]?enabled|allow_introspection)\s*[:=]\s*true/i;
  lines.forEach((line, i) => {
    if (isCommentLine(line)) return;
    if (re.test(line)) {
      addFinding(
        findings, path, i + 1, line, 'GRAPHQL_INTROSPECTION_ENABLED', 'LOW',
        'GraphQL schema introspection is enabled',
        'Introspection (__schema/__type) is left on, letting any client enumerate the full schema, including unintended fields.',
        'Disable introspection in production, or gate it behind authentication for internal/dev use only.'
      );
    }
  });
}

const PASSES = [
  scanHardcodedSecrets,
  scanInsecureRandom,
  scanDangerousEval,
  scanUnsafeNetworking,
  scanSqlInjection,
  scanPathTraversal,
  scanCommandInjection,
  scanWeakCryptography,
  scanSensitiveLogging,
  scanInsecureDeserialization,
  scanRpcExposure,
  scanTimingUnsafeComparison,
  scanInsecureCors,
  scanStackTraceExposure,
  scanOpenRedirect,
  scanGraphqlIntrospectionEnabled,
];

/**
 * Scans a single GDScript source string and returns an array of findings.
 * @param {string} filePath - logical path, used only for reporting.
 * @param {string} source - full file contents.
 */
function scanSource(filePath, source) {
  const lines = source.split(/\r?\n/);
  const findings = [];
  for (const pass of PASSES) {
    pass(filePath, lines, findings);
  }
  return findings;
}

module.exports = { scanSource, PASSES_COUNT: PASSES.length };
