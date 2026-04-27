import React, { useEffect, useRef, useState } from 'react';

const SEVERITY_COLOR = {
  critical: '#b91c1c',
  high: '#c2410c',
  medium: '#a16207',
  low: '#15803d',
  none: '#3fb950',
};

function getRiskColor(score) {
  if (score >= 9) return '#b91c1c';
  if (score >= 7) return '#c2410c';
  if (score >= 4) return '#a16207';
  if (score > 0) return '#eab308';
  return '#3fb950';
}

function getRiskLabel(score) {
  if (score >= 9) return 'KRİTİK';
  if (score >= 7) return 'YÜKSEK';
  if (score >= 4) return 'ORTA';
  if (score > 0) return 'DÜŞÜK';
  return 'TEMİZ';
}

function getDeviceIcon(host) {
  const services = host.ports.map(p => p.service);
  const banner = host.ports.map(p => p.version || '').join(' ').toLowerCase();

  if (services.includes('ms-wbt-server') || services.includes('microsoft-ds')) return '🖥️';
  if (services.includes('ssh') && services.includes('http')) return '🖧';
  if (banner.includes('apache') || banner.includes('nginx') || banner.includes('tomcat')) return '🌐';
  if (services.includes('ftp') || services.includes('smtp')) return '📦';
  if (services.includes('mysql') || services.includes('postgresql')) return '🗄️';
  if (services.includes('ssh')) return '💻';
  if (services.includes('domain')) return '📡';
  return '🖥️';
}

function getDeviceType(host) {
  const services = host.ports.map(p => p.service);
  const banner = host.ports.map(p => p.version || '').join(' ').toLowerCase();

  if (banner.includes('apache') || banner.includes('nginx') || banner.includes('tomcat')) return 'Web Server';
  if (services.includes('mysql') || services.includes('postgresql')) return 'Database';
  if (services.includes('microsoft-ds') || services.includes('netbios-ssn')) return 'Windows Host';
  if (services.includes('ssh') && services.includes('ftp')) return 'FTP/SSH Server';
  if (services.includes('ssh')) return 'Linux Host';
  if (services.includes('domain')) return 'DNS Server';
  if (services.includes('smtp')) return 'Mail Server';
  return 'Host';
}

export default function NetworkMap({ hosts, target }) {
  const svgRef = useRef(null);
  const [selected, setSelected] = useState(null);
  const [tooltip, setTooltip] = useState(null);

  // --- MANTIKSAL DÜZELTME BURADA YAPILDI ---
  const rawHosts = Array.isArray(hosts) ? hosts : Object.values(hosts || {});

  const hostList = rawHosts.map(host => {
    // Toplam CVE sayısını hesapla
    const cveCount = host.ports?.reduce((a, p) => a + (p.cves?.length || 0), 0) || 0;
    let correctedRisk = host.risk_score || 0;

    // KURAL 1: Siber Güvenlikte risk ortalaması alınmaz. Bir sistemin riski, en yüksek riskli portu kadardır.
    const maxPortRisk = Math.max(0, ...(host.ports?.map(p => p.risk_score || 0) || []));
    if (maxPortRisk > correctedRisk) {
      correctedRisk = maxPortRisk;
    }

    // KURAL 2: Eğer bir sistemde çok fazla (örn. 10+) CVE varsa, matematiksel skoru düşük kalsa bile KRİTİK (Kırmızı) sayılmalıdır.
    if (cveCount >= 10 && correctedRisk < 9) {
      correctedRisk = 9.8;
    } else if (cveCount >= 5 && correctedRisk < 7) {
      correctedRisk = 7.5; // 5'ten fazla CVE varsa en az Turuncu olur
    }

    // host objesini güvenli risk skoruyla güncelleyerek döndür
    return { ...host, original_risk: host.risk_score, risk_score: correctedRisk, cveCount };
  });

  if (!hostList || hostList.length === 0) return null;

  // Layout hesapla
  const WIDTH = 900;
  const HEIGHT = 420;
  const CX = WIDTH / 2;
  const CY = HEIGHT / 2 - 20;
  const RADIUS = hostList.length <= 4 ? 150 : hostList.length <= 8 ? 180 : 200;

  const nodePositions = hostList.map((host, i) => {
    const angle = (2 * Math.PI * i) / hostList.length - Math.PI / 2;
    return {
      x: CX + RADIUS * Math.cos(angle),
      y: CY + RADIUS * Math.sin(angle),
      host,
    };
  });

  const totalCves = hostList.reduce((acc, h) => acc + h.cveCount, 0);
  const maxRisk = Math.max(...hostList.map(h => h.risk_score || 0));

  return (
    <div style={{
      background: '#0d1117',
      border: '1px solid #30363d',
      borderRadius: '10px',
      padding: '20px',
      marginBottom: '0',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div>
          <h3 style={{ color: '#e6edf3', fontSize: '15px', fontWeight: '700', margin: 0 }}>
            🗺️ Network Haritası
          </h3>
          <p style={{ color: '#8b949e', fontSize: '12px', margin: '4px 0 0' }}>
            {hostList.length} cihaz tespit edildi · {totalCves} CVE · Max Risk: {maxRisk.toFixed(1)}
          </p>
        </div>
        {selected && (
          <button
            onClick={() => setSelected(null)}
            style={{
              background: 'transparent',
              border: '1px solid #30363d',
              color: '#8b949e',
              borderRadius: '6px',
              padding: '4px 12px',
              cursor: 'pointer',
              fontSize: '12px',
            }}
          >
            ✕ Kapat
          </button>
        )}
      </div>

      <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
        {/* SVG Harita */}
        <div style={{ flex: '1', minWidth: '300px', position: 'relative' }}>
          <svg
            ref={svgRef}
            width="100%"
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            style={{ background: '#0d1117', borderRadius: '8px', border: '1px solid #21262d' }}
          >
            {/* Izgara arka planı */}
            <defs>
              <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#161b22" strokeWidth="1" />
              </pattern>
              <radialGradient id="routerGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#1f6feb" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#1f6feb" stopOpacity="0" />
              </radialGradient>
              {nodePositions.map((n, i) => (
                <radialGradient key={i} id={`glow${i}`} cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor={getRiskColor(n.host.risk_score)} stopOpacity="0.25" />
                  <stop offset="100%" stopColor={getRiskColor(n.host.risk_score)} stopOpacity="0" />
                </radialGradient>
              ))}
            </defs>

            <rect width={WIDTH} height={HEIGHT} fill="url(#grid)" />

            {/* Bağlantı çizgileri */}
            {nodePositions.map((node, i) => (
              <g key={i}>
                <line
                  x1={CX} y1={CY}
                  x2={node.x} y2={node.y}
                  stroke="#21262d"
                  strokeWidth="1.5"
                  strokeDasharray="6 3"
                />
                {/* Animasyonlu paket */}
                <circle r="3" fill="#1f6feb" opacity="0.7">
                  <animateMotion
                    dur={`${2 + i * 0.4}s`}
                    repeatCount="indefinite"
                    path={`M ${CX} ${CY} L ${node.x} ${node.y}`}
                  />
                </circle>
              </g>
            ))}

            {/* Router merkez node */}
            <g
              style={{ cursor: 'pointer' }}
              onClick={() => setSelected(null)}
            >
              <circle cx={CX} cy={CY} r={48} fill="url(#routerGlow)" />
              <circle
                cx={CX} cy={CY} r={32}
                fill="#161b22"
                stroke="#1f6feb"
                strokeWidth="2"
              />
              <text x={CX} y={CY - 4} textAnchor="middle" fontSize="18" dominantBaseline="middle">🌐</text>
              <text x={CX} y={CY + 18} textAnchor="middle" fontSize="9" fill="#58a6ff" fontFamily="monospace">
                {target?.split('/')[0] || 'Router'}
              </text>
            </g>

            {/* Host node'ları */}
            {nodePositions.map((node, i) => {
              const riskColor = getRiskColor(node.host.risk_score);
              const isSelected = selected?.ip === node.host.ip;
              const hasCves = node.host.cveCount > 0;

              return (
                <g
                  key={i}
                  style={{ cursor: 'pointer' }}
                  onClick={() => setSelected(isSelected ? null : node.host)}
                  onMouseEnter={() => setTooltip({ ...node, index: i })}
                  onMouseLeave={() => setTooltip(null)}
                >
                  {/* Glow */}
                  <circle cx={node.x} cy={node.y} r={50} fill={`url(#glow${i})`} />

                  {/* Risk halkası */}
                  <circle
                    cx={node.x} cy={node.y} r={30}
                    fill="none"
                    stroke={riskColor}
                    strokeWidth={isSelected ? 3 : 1.5}
                    strokeDasharray={hasCves ? "none" : "4 2"}
                    opacity={isSelected ? 1 : 0.7}
                  />

                  {/* Ana çember */}
                  <circle
                    cx={node.x} cy={node.y} r={26}
                    fill={isSelected ? '#1c2128' : '#161b22'}
                    stroke={riskColor}
                    strokeWidth={isSelected ? 2 : 1}
                  />

                  {/* İkon */}
                  <text
                    x={node.x} y={node.y - 4}
                    textAnchor="middle"
                    fontSize="14"
                    dominantBaseline="middle"
                  >
                    {getDeviceIcon(node.host)}
                  </text>

                  {/* Risk skoru */}
                  <text
                    x={node.x} y={node.y + 14}
                    textAnchor="middle"
                    fontSize="8"
                    fill={riskColor}
                    fontFamily="monospace"
                    fontWeight="bold"
                  >
                    {node.host.risk_score?.toFixed(1)}
                  </text>

                  {/* IP etiketi */}
                  <text
                    x={node.x} y={node.y + 44}
                    textAnchor="middle"
                    fontSize="9"
                    fill={isSelected ? '#58a6ff' : '#8b949e'}
                    fontFamily="monospace"
                  >
                    {node.host.ip}
                  </text>

                  {/* CVE uyarı rozeti */}
                  {hasCves && (
                    <g>
                      <circle cx={node.x + 22} cy={node.y - 22} r={8} fill={riskColor} />
                      <text
                        x={node.x + 22} y={node.y - 22}
                        textAnchor="middle"
                        dominantBaseline="middle"
                        fontSize="8"
                        fill="white"
                        fontWeight="bold"
                      >
                        {node.host.cveCount}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {/* Tooltip */}
            {tooltip && (
              <g>
                <rect
                  x={Math.min(tooltip.x + 36, WIDTH - 180)}
                  y={Math.max(tooltip.y - 60, 8)}
                  width={175}
                  height={70}
                  rx={6}
                  fill="#161b22"
                  stroke="#30363d"
                  strokeWidth="1"
                />
                <text
                  x={Math.min(tooltip.x + 46, WIDTH - 170)}
                  y={Math.max(tooltip.y - 42, 22)}
                  fontSize="10"
                  fill="#58a6ff"
                  fontFamily="monospace"
                  fontWeight="bold"
                >
                  {tooltip.host.ip}
                </text>
                <text
                  x={Math.min(tooltip.x + 46, WIDTH - 170)}
                  y={Math.max(tooltip.y - 28, 36)}
                  fontSize="9"
                  fill="#8b949e"
                >
                  {getDeviceType(tooltip.host)}
                </text>
                <text
                  x={Math.min(tooltip.x + 46, WIDTH - 170)}
                  y={Math.max(tooltip.y - 16, 48)}
                  fontSize="9"
                  fill="#8b949e"
                >
                  {tooltip.host.ports?.length || 0} port · {tooltip.host.cveCount} CVE
                </text>
                <text
                  x={Math.min(tooltip.x + 46, WIDTH - 170)}
                  y={Math.max(tooltip.y - 4, 60)}
                  fontSize="9"
                  fill={getRiskColor(tooltip.host.risk_score)}
                  fontWeight="bold"
                >
                  Risk: {tooltip.host.risk_score?.toFixed(1)} — {getRiskLabel(tooltip.host.risk_score)}
                </text>
              </g>
            )}
          </svg>

          {/* Legend */}
          <div style={{ display: 'flex', gap: '16px', marginTop: '10px', flexWrap: 'wrap' }}>
            {[['#b91c1c', 'Kritik (9+)'], ['#c2410c', 'Yüksek (7+)'], ['#a16207', 'Orta (4+)'], ['#eab308', 'Düşük (>0)'], ['#3fb950', 'Temiz']].map(([color, label]) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: color }} />
                <span style={{ color: '#8b949e', fontSize: '11px' }}>{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Seçili host detay paneli */}
        {selected && (
          <div style={{
            width: '260px',
            background: '#161b22',
            border: '1px solid #30363d',
            borderRadius: '8px',
            padding: '16px',
            fontSize: '13px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <span style={{ fontSize: '20px' }}>{getDeviceIcon(selected)}</span>
              <div>
                <div style={{ color: '#58a6ff', fontWeight: '700', fontFamily: 'monospace', fontSize: '14px' }}>
                  {selected.ip}
                </div>
                <div style={{ color: '#8b949e', fontSize: '11px' }}>{getDeviceType(selected)}</div>
              </div>
            </div>

            <div style={{
              background: '#0d1117',
              borderRadius: '6px',
              padding: '8px 12px',
              marginBottom: '12px',
              border: `1px solid ${getRiskColor(selected.risk_score)}40`,
            }}>
              <div style={{ color: '#8b949e', fontSize: '11px', marginBottom: '4px' }}>Risk Skoru</div>
              <div style={{ color: getRiskColor(selected.risk_score), fontWeight: '700', fontSize: '22px' }}>
                {selected.risk_score?.toFixed(1)}
                <span style={{ fontSize: '12px', color: '#8b949e', marginLeft: '6px' }}>/ 10</span>
              </div>
              <div style={{ color: getRiskColor(selected.risk_score), fontSize: '11px', fontWeight: '600' }}>
                {getRiskLabel(selected.risk_score)}
              </div>
            </div>

            <div style={{ color: '#8b949e', fontSize: '11px', fontWeight: '600', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Açık Portlar
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '280px', overflowY: 'auto' }}>
              {selected.ports?.map((port, i) => {
                const portRiskColor = getRiskColor(port.risk_score || 0);
                const cveCount = port.cves?.length || 0;

                return (
                  <div key={i} style={{
                    background: '#0d1117',
                    border: `1px solid ${cveCount > 0 ? portRiskColor + '40' : '#21262d'}`,
                    borderRadius: '6px',
                    padding: '8px 10px',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{
                          background: '#21262d',
                          color: '#79c0ff',
                          fontFamily: 'monospace',
                          fontSize: '11px',
                          fontWeight: '700',
                          padding: '1px 6px',
                          borderRadius: '3px',
                        }}>
                          {port.port}
                        </span>
                        <span style={{ color: '#c9d1d9', fontSize: '12px', fontWeight: '600' }}>
                          {port.service}
                        </span>
                      </div>
                      {cveCount > 0 && (
                        <span style={{
                          background: portRiskColor + '20',
                          color: portRiskColor,
                          border: `1px solid ${portRiskColor}`,
                          borderRadius: '3px',
                          fontSize: '10px',
                          fontWeight: '700',
                          padding: '1px 5px',
                        }}>
                          {cveCount} CVE
                        </span>
                      )}
                    </div>
                    {port.version && port.version !== '-' && (
                      <div style={{ color: '#8b949e', fontSize: '10px', marginTop: '3px' }}>
                        {port.version.length > 35 ? port.version.substring(0, 35) + '…' : port.version}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}