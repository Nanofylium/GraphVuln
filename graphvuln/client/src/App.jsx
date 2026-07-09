import { useState, useMemo, useEffect } from 'react';
import { scanProject, fetchScenarios, runScenario, exportReport, downloadText } from './api';
import './App.css';

const SEVERITY_COLORS = {
  CRITICAL: '#e5484d',
  HIGH: '#f2994a',
  MEDIUM: '#e0c341',
  LOW: '#3d9df3',
};

function SeverityBadge({ severity }) {
  return (
    <span className="badge" style={{ backgroundColor: SEVERITY_COLORS[severity] || '#888' }}>
      {severity}
    </span>
  );
}

function SummaryCards({ counts }) {
  return (
    <div className="summary-cards">
      {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
        <div className="summary-card" key={sev} style={{ borderColor: SEVERITY_COLORS[sev] }}>
          <div className="summary-count">{counts[sev] || 0}</div>
          <div className="summary-label">{sev}</div>
        </div>
      ))}
    </div>
  );
}

function FindingsTable({ findings, selected, onSelect }) {
  if (findings.length === 0) {
    return <p className="empty-state">Nenhum achado — rode um scan pra começar.</p>;
  }
  return (
    <table className="findings-table">
      <thead>
        <tr>
          <th>Severidade</th>
          <th>Título</th>
          <th>Local</th>
          <th>CWE</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f) => (
          <tr
            key={f.id}
            className={selected?.id === f.id ? 'selected' : ''}
            onClick={() => onSelect(f)}
          >
            <td><SeverityBadge severity={f.severity} /></td>
            <td>{f.title}</td>
            <td className="mono">
              {(f.filePath || f.resourcePath || '')}{f.lineNumber ? `:${f.lineNumber}` : ''}
            </td>
            <td>{f.cwe ? f.cwe.id : '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DetailPanel({ finding }) {
  if (!finding) {
    return <div className="detail-panel empty">Selecione um achado pra ver detalhes.</div>;
  }
  return (
    <div className="detail-panel">
      <h3>{finding.title}</h3>
      <SeverityBadge severity={finding.severity} />
      {finding.cwe && (
        <a className="cwe-link" href={finding.cwe.url} target="_blank" rel="noreferrer">
          {finding.cwe.id} — {finding.cwe.name}
        </a>
      )}
      <p className="detail-section-label">Descrição</p>
      <p>{finding.description}</p>
      <p className="detail-section-label">Remediação</p>
      <p>{finding.remediation}</p>
      {finding.lineText && (
        <>
          <p className="detail-section-label">Linha</p>
          <pre className="code-line">{finding.lineText}</pre>
        </>
      )}
    </div>
  );
}

function ScenarioPanel() {
  const [scenarios, setScenarios] = useState([]);
  const [selected, setSelected] = useState('');
  const [target, setTarget] = useState('');
  const [payload, setPayload] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchScenarios().then((d) => {
      setScenarios(d.scenarios || []);
      if (d.scenarios?.length) setSelected(d.scenarios[0]);
    });
  }, []);

  async function handleRun() {
    setLoading(true);
    try {
      const r = await runScenario(selected, { target, payload });
      setResult(r);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="scenario-panel">
      <h3>Simulador de cenários</h3>
      <p className="scenario-disclaimer">
        Isto <strong>simula</strong> e descreve um cenário de ataque — não executa nada contra um
        alvo real. Use pra documentar o impacto hipotético de um achado no laudo.
      </p>
      <div className="scenario-form">
        <select value={selected} onChange={(e) => setSelected(e.target.value)}>
          {scenarios.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input placeholder="Alvo (ex: UserLoginResolver)" value={target} onChange={(e) => setTarget(e.target.value)} />
        <input placeholder="Payload / path / command (opcional)" value={payload} onChange={(e) => setPayload(e.target.value)} />
        <button onClick={handleRun} disabled={loading || !selected}>
          {loading ? 'Rodando…' : 'Simular'}
        </button>
      </div>
      {result && (
        <pre className="scenario-result">{JSON.stringify(result, null, 2)}</pre>
      )}
    </div>
  );
}

export default function App() {
  const [projectDir, setProjectDir] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');

  const allFindings = scanResult?.report?.findings || [];
  const filteredFindings = useMemo(() => {
    if (severityFilter === 'ALL') return allFindings;
    return allFindings.filter((f) => f.severity === severityFilter);
  }, [allFindings, severityFilter]);

  async function handleScan() {
    setScanning(true);
    setError('');
    try {
      const result = await scanProject(projectDir);
      setScanResult(result);
      setSelectedFinding(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setScanning(false);
    }
  }

  async function handleExport(format) {
    if (!scanResult) return;
    const text = await exportReport(format, scanResult.codeFindings, scanResult.resourceFindings);
    const ext = { json: 'json', sarif: 'sarif.json', csv: 'csv', markdown: 'md' }[format];
    const mime = { json: 'application/json', sarif: 'application/json', csv: 'text/csv', markdown: 'text/markdown' }[format];
    downloadText(`graphvuln-report.${ext}`, text, mime);
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="logo-mark" />
        <div>
          <h1>GraphVuln</h1>
          <p className="tagline">Forense de segurança para GDScript &amp; GraphQL</p>
        </div>
      </header>

      <section className="scan-controls">
        <input
          className="project-input"
          placeholder="Caminho absoluto do projeto (ex: /home/user/meu-jogo)"
          value={projectDir}
          onChange={(e) => setProjectDir(e.target.value)}
        />
        <button className="scan-button" onClick={handleScan} disabled={scanning || !projectDir}>
          {scanning ? 'Escaneando…' : 'Scan Project'}
        </button>
      </section>

      {error && <p className="error-banner">{error}</p>}

      {scanResult && (
        <>
          <p className="scan-meta">
            {scanResult.filesScanned} arquivos ({scanResult.gdFilesScanned} .gd) escaneados em{' '}
            <span className="mono">{scanResult.projectDir}</span>
          </p>

          <SummaryCards counts={scanResult.report.summary.bySeverity} />

          <div className="export-row">
            {['json', 'sarif', 'csv', 'markdown'].map((fmt) => (
              <button key={fmt} className="export-button" onClick={() => handleExport(fmt)}>
                Exportar {fmt.toUpperCase()}
              </button>
            ))}
          </div>

          <div className="severity-filter">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                className={`filter-chip ${severityFilter === sev ? 'active' : ''}`}
                onClick={() => setSeverityFilter(sev)}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="main-grid">
            <FindingsTable
              findings={filteredFindings}
              selected={selectedFinding}
              onSelect={setSelectedFinding}
            />
            <DetailPanel finding={selectedFinding} />
          </div>
        </>
      )}

      <ScenarioPanel />
    </div>
  );
}
