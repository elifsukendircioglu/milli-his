import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { startScan, getScans, getReport } from '../services/api';
import NetworkMap from './NetworkMap';
import './Dashboard.css';

const severityColor = {
  Critical: '#b91c1c',
  High: '#c2410c',
  Medium: '#a16207',
  Low: '#15803d',
};

const severityBg = {
  Critical: 'rgba(185,28,28,0.15)',
  High: 'rgba(194,65,12,0.15)',
  Medium: 'rgba(161,98,7,0.15)',
  Low: 'rgba(21,128,61,0.15)',
};

function SeverityBadge({ severity }) {
  if (!severity) return null;
  return (
    <span style={{
      background: severityBg[severity] || 'rgba(100,100,100,0.15)',
      color: severityColor[severity] || '#8b949e',
      border: `1px solid ${severityColor[severity] || '#8b949e'}`,
      borderRadius: '4px',
      padding: '2px 8px',
      fontSize: '11px',
      fontWeight: '700',
      letterSpacing: '0.5px',
      textTransform: 'uppercase',
    }}>
      {severity}
    </span>
  );
}

function RiskBar({ score }) {
  const pct = Math.min((score / 10) * 100, 100);
  const color = score >= 9 ? '#b91c1c' : score >= 7 ? '#c2410c' : score >= 4 ? '#a16207' : '#15803d';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
      <div style={{ flex: 1, height: '8px', background: '#21262d', borderRadius: '4px', overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: '4px', transition: 'width 0.6s ease' }} />
      </div>
      <span style={{ color, fontWeight: '700', fontSize: '14px', minWidth: '32px' }}>
        {score?.toFixed(1)}
      </span>
    </div>
  );
}

function PortTable({ ports }) {
  return (
    <div className="table-wrapper">
      <table className="result-table">
        <thead>
          <tr>
            <th>Port</th>
            <th>Protokol</th>
            <th>Servis</th>
            <th>Versiyon</th>
            <th>Durum</th>
            <th>CVE'ler</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((port, idx) => (
            <tr key={idx}>
              <td><span className="port-badge">{port.port}</span></td>
              <td style={{ color: '#8b949e', fontSize: '12px' }}>{port.protocol || 'tcp'}</td>
              <td style={{ fontWeight: '600' }}>{port.service || '-'}</td>
              <td style={{ color: '#8b949e', fontSize: '13px' }}>{port.version || '-'}</td>
              <td><span className="status-open">açık</span></td>
              <td>
                {port.cves && port.cves.length > 0 ? (
                  <div className="cve-list">
                    {port.cves.map((cve, ci) => (
                      <div key={ci} className="cve-item">
                        <div className="cve-top">
                          <span className="cve-id">{cve.id}</span>
                          <SeverityBadge severity={cve.severity} />
                          {cve.cvss_score && (
                            <span className="cvss-score">CVSS: {cve.cvss_score}</span>
                          )}
                        </div>
                        {cve.description && (
                          <p className="cve-desc">{cve.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <span style={{ color: '#3fb950', fontSize: '12px' }}>✓ Zafiyet bulunamadı</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HostCard({ host, index }) {
  const [expanded, setExpanded] = useState(true);
  const hasCves = host.ports.some(p => p.cves && p.cves.length > 0);
  const riskColor = host.risk_score >= 9 ? '#b91c1c' : host.risk_score >= 7 ? '#c2410c' : host.risk_score >= 4 ? '#a16207' : '#15803d';

  return (
    <div className="host-card">
      <div className="host-card-header" onClick={() => setExpanded(!expanded)}>
        <div className="host-card-left">
          <span className="host-index">#{index + 1}</span>
          <span className="host-ip">{host.ip}</span>
          {host.hostname && <span className="host-hostname">({host.hostname})</span>}
          <span className="host-ports-count">{host.ports.length} açık port</span>
          {hasCves && <span className="host-vuln-badge">⚠ Zafiyet Tespit Edildi</span>}
        </div>
        <div className="host-card-right">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ color: '#8b949e', fontSize: '12px' }}>Risk:</span>
            <span style={{ color: riskColor, fontWeight: '700', fontSize: '16px' }}>
              {host.risk_score?.toFixed(1)}
            </span>
          </div>
          <span className="host-toggle">{expanded ? '▲' : '▼'}</span>
        </div>
      </div>
      {expanded && (
        <div className="host-card-body">
          <div style={{ marginBottom: '12px', maxWidth: '400px' }}>
            <RiskBar score={host.risk_score || 0} />
          </div>
          {host.ports.length > 0 ? (
            <PortTable ports={host.ports} />
          ) : (
            <div className="no-ports">Bu hostta açık port bulunamadı.</div>
          )}
        </div>
      )}
    </div>
  );
}

function Dashboard() {
  const navigate = useNavigate();
  const username = localStorage.getItem('username') || 'Kullanıcı';
  const [target, setTarget] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState('');
  const [downloadingId, setDownloadingId] = useState(null);

  useEffect(() => { loadHistory(); }, []);

  const loadHistory = async () => {
    try {
      const data = await getScans();
      setHistory(data);
    } catch {}
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    setError('');
    setScanResult(null);
    setScanning(true);
    try {
      const data = await startScan(target.trim());
      setScanResult(data);
      setScanId(data.scan_id);
      loadHistory();
    } catch (err) {
      setError(err.response?.data?.detail || 'Tarama başarısız. Hedef erişilebilir mi?');
    } finally {
      setScanning(false);
    }
  };

  const handleDownload = async (id) => {
    setDownloadingId(id);
    try {
      const blob = await getReport(id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `milli-his-rapor-${id}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      alert('PDF indirilemedi.');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    navigate('/login');
  };

  const hosts = scanResult?.hosts || (
    scanResult?.ports?.length > 0
      ? [{ ip: scanResult?.target, hostname: '', risk_score: scanResult?.risk_score, ports: scanResult?.ports }]
      : []
  );

  const totalHosts = hosts.length;
  const totalPorts = hosts.reduce((acc, h) => acc + h.ports.length, 0);
  const totalCves = hosts.reduce((acc, h) => acc + h.ports.reduce((a, p) => a + (p.cves?.length || 0), 0), 0);
  const criticalHosts = hosts.filter(h => h.risk_score >= 9).length;

  return (
    <div className="dashboard">
      <header className="dash-header">
        <div className="dash-header-left">
          <span className="dash-logo">🛡️ Milli HİS</span>
          <span className="dash-version">v1.0</span>
        </div>
        <div className="dash-header-right">
          <span className="dash-user">👤 {username}</span>
          <button className="btn-logout" onClick={handleLogout}>Çıkış</button>
        </div>
      </header>

      <main className="dash-main">
        <section className="scan-section">
          <h2 className="section-title">Yeni Tarama</h2>
          <form className="scan-form" onSubmit={handleScan}>
            <input
              className="scan-input"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Hedef IP veya CIDR (örn: 192.168.1.1 veya 192.168.1.0/24)"
              disabled={scanning}
            />
            <button className="btn-scan" type="submit" disabled={scanning}>
              {scanning ? <><span className="spinner" /> Taranıyor...</> : '🔍 Tara'}
            </button>
          </form>
          {error && <div className="error-msg" style={{ marginTop: '12px' }}>{error}</div>}
        </section>

        {scanResult && (
          <section className="result-section">
            <div className="result-header">
              <div>
                <h2 className="section-title">
                  Tarama Sonucu — <span style={{ color: '#58a6ff' }}>{scanResult.target}</span>
                </h2>
                <div style={{ marginTop: '8px', maxWidth: '300px' }}>
                  <span style={{ color: '#8b949e', fontSize: '13px' }}>Genel Risk Skoru:</span>
                  <div style={{ marginTop: '6px' }}>
                    <RiskBar score={scanResult.risk_score || 0} />
                  </div>
                </div>
              </div>
              <button
                className="btn-pdf"
                onClick={() => handleDownload(scanId)}
                disabled={downloadingId === scanId}
              >
                {downloadingId === scanId ? '⏳ İndiriliyor...' : '📄 PDF İndir'}
              </button>
            </div>

            {totalHosts > 0 && (
              <div className="summary-cards">
                <div className="summary-card">
                  <span className="summary-num">{totalHosts}</span>
                  <span className="summary-label">Aktif Host</span>
                </div>
                <div className="summary-card">
                  <span className="summary-num">{totalPorts}</span>
                  <span className="summary-label">Açık Port</span>
                </div>
                <div className="summary-card">
                  <span className="summary-num" style={{ color: totalCves > 0 ? '#f85149' : '#3fb950' }}>
                    {totalCves}
                  </span>
                  <span className="summary-label">Toplam CVE</span>
                </div>
                <div className="summary-card">
                  <span className="summary-num" style={{ color: criticalHosts > 0 ? '#b91c1c' : '#3fb950' }}>
                    {criticalHosts}
                  </span>
                  <span className="summary-label">Kritik Host</span>
                </div>
              </div>
            )}

            {/* Network Haritası */}
            {hosts.length > 0 && (
              <NetworkMap hosts={hosts} target={scanResult.target} />
            )}

            {hosts.length > 0 ? (
              <div className="hosts-list" style={{ marginTop: '16px' }}>
                {hosts.map((host, idx) => (
                  <HostCard key={idx} host={host} index={idx} />
                ))}
              </div>
            ) : (
              <div className="no-ports">Aktif host bulunamadı veya hedefe ulaşılamadı.</div>
            )}
          </section>
        )}

        <section className="history-section">
          <h2 className="section-title">Tarama Geçmişi</h2>
          {history.length === 0 ? (
            <p style={{ color: '#8b949e', fontSize: '14px' }}>Henüz tarama yapılmamış.</p>
          ) : (
            <div className="table-wrapper">
              <table className="result-table">
                <thead>
                  <tr>
                    <th>#</th>
                    <th>Hedef</th>
                    <th>Risk Skoru</th>
                    <th>Durum</th>
                    <th>Tarih</th>
                    <th>İşlem</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((scan) => (
                    <tr key={scan.id}>
                      <td style={{ color: '#8b949e' }}>{scan.id}</td>
                      <td style={{ fontWeight: '600', color: '#58a6ff' }}>{scan.target}</td>
                      <td style={{ maxWidth: '160px' }}>
                        <RiskBar score={scan.risk_score || 0} />
                      </td>
                      <td>
                        <span style={{ color: scan.status === 'done' ? '#3fb950' : '#f85149', fontSize: '12px', fontWeight: '600' }}>
                          {scan.status === 'done' ? '✓ Tamamlandı' : scan.status}
                        </span>
                      </td>
                      <td style={{ color: '#8b949e', fontSize: '12px' }}>
                        {new Date(scan.scanned_at).toLocaleString('tr-TR')}
                      </td>
                      <td>
                        <button
                          className="btn-pdf-sm"
                          onClick={() => handleDownload(scan.id)}
                          disabled={downloadingId === scan.id}
                        >
                          {downloadingId === scan.id ? '⏳' : '📄 PDF'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default Dashboard;