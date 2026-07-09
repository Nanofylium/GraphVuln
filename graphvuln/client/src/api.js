const API_BASE = 'http://localhost:4123';

export async function scanProject(projectDir) {
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ projectDir }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Scan failed');
  return data;
}

export async function fetchScenarios() {
  const res = await fetch(`${API_BASE}/api/scenarios`);
  return res.json();
}

export async function runScenario(name, params) {
  const res = await fetch(`${API_BASE}/api/scenarios/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  return res.json();
}

export async function exportReport(format, codeFindings, resourceFindings) {
  const res = await fetch(`${API_BASE}/api/export/${format}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ codeFindings, resourceFindings }),
  });
  return res.text();
}

export function downloadText(filename, text, mime = 'text/plain') {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
