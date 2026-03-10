import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { getStats, getThreats } from '../api'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

export default function Dashboard() {
  const [stats,   setStats]   = useState(null)
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  // Read role once at component level — reliable
  const role     = localStorage.getItem('role')
  const username = localStorage.getItem('user')
  const isAdmin  = role === 'admin'

  // ── Logout ─────────────────────────────────────────────
  const logout = () => {
    localStorage.clear()
    navigate('/login', { replace: true })
  }

  // ── Load Data ──────────────────────────────────────────
  useEffect(() => {
    const load = async () => {
      try {
        const [s, t] = await Promise.all([getStats(), getThreats()])
        setStats(s.data)
        setThreats(t.data.slice(0, 10))
      } catch (err) {
        if (err?.response?.status === 401) {
          localStorage.clear()
          navigate('/login', { replace: true })
        }
      } finally {
        setLoading(false)
      }
    }
    load()
    const interval = setInterval(load, 10000)
    return () => clearInterval(interval)
  }, [])

  // ── Card Config ────────────────────────────────────────
  const cards = stats ? [
    { label: 'TOTAL SCANNED',    value: stats.total_scanned,       color: '#00d4ff', icon: '📁' },
    { label: 'ACTIVE THREATS',   value: stats.active_threats,      color: '#ff003c', icon: '🚨' },
    { label: 'HIGH RISK ALERTS', value: stats.high_risk_alerts,    color: '#ff8c00', icon: '⚠️'  },
    { label: 'SYSTEM HEALTH',    value: `${stats.system_health}%`, color: '#00ff88', icon: '💚' },
  ] : []

  // ── Nav Button Style ───────────────────────────────────
  const navBtn = (color = '#00d4ff') => ({
    padding: '8px 16px',
    fontSize: 11,
    fontFamily: 'monospace',
    fontWeight: 'bold',
    letterSpacing: 2,
    background: 'transparent',
    border: `1px solid ${color}`,
    borderRadius: 6,
    color: color,
    cursor: 'pointer',
    transition: 'all 0.2s',
    textDecoration: 'none',
    display: 'inline-block'
  })

  return (
    <div style={{ minHeight: '100vh', background: '#000010', padding: 24 }}>

      {/* ── Header ─────────────────────────────────────── */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 28,
        flexWrap: 'wrap',
        gap: 16
      }}>

        {/* Title */}
        <div>
          <h1 style={{
            color: '#fff',
            fontFamily: 'monospace',
            fontSize: 20,
            fontWeight: 'bold',
            letterSpacing: 4,
            margin: '0 0 4px'
          }}>
            🛡️ CYBERDEFENSE SOC
          </h1>
          <p style={{
            color: '#444',
            fontFamily: 'monospace',
            fontSize: 11,
            margin: 0,
            letterSpacing: 2
          }}>
            Welcome,{' '}
            <span style={{ color: '#00d4ff' }}>{username}</span>
            {' '}—{' '}
            <span style={{ color: isAdmin ? '#ff003c' : '#00d4ff' }}>
              {role?.toUpperCase()}
            </span>
          </p>
        </div>

        {/* Nav Buttons */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>

          <Link to="/threats" style={navBtn('#00d4ff')}
            onMouseEnter={e => { e.target.style.background = '#00d4ff'; e.target.style.color = '#000' }}
            onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = '#00d4ff' }}>
            ⚡ THREATS
          </Link>

          <Link to="/analytics" style={navBtn('#00d4ff')}
            onMouseEnter={e => { e.target.style.background = '#00d4ff'; e.target.style.color = '#000' }}
            onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = '#00d4ff' }}>
            📊 ANALYTICS
          </Link>

          <Link to="/blockchain" style={navBtn('#00d4ff')}
            onMouseEnter={e => { e.target.style.background = '#00d4ff'; e.target.style.color = '#000' }}
            onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = '#00d4ff' }}>
            ⛓️ BLOCKCHAIN
          </Link>

          <Link to="/soc" style={navBtn('#00ff88')}
            onMouseEnter={e => { e.target.style.background = '#00ff88'; e.target.style.color = '#000' }}
            onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = '#00ff88' }}>
            🖥 SOC
          </Link>

          <Link to="/chat" style={navBtn('#ff8c00')}
            onMouseEnter={e => { e.target.style.background = '#ff8c00'; e.target.style.color = '#000' }}
            onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = '#ff8c00' }}>
            🤖 AI CHAT
          </Link>

          {/* ADMIN — only visible to admin role */}
          {isAdmin && (
            <Link to="/admin" style={navBtn('#ff003c')}
              onMouseEnter={e => { e.target.style.background = '#ff003c'; e.target.style.color = '#000' }}
              onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = '#ff003c' }}>
              ⚙️ ADMIN
            </Link>
          )}

          <button onClick={logout} style={navBtn('#ff003c')}
            onMouseEnter={e => { e.target.style.background = '#ff003c'; e.target.style.color = '#000' }}
            onMouseLeave={e => { e.target.style.background = 'transparent'; e.target.style.color = '#ff003c' }}>
            🚪 LOGOUT
          </button>

        </div>
      </div>

      {/* ── Loading ─────────────────────────────────────── */}
      {loading && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          height: 300,
          flexDirection: 'column',
          gap: 16
        }}>
          <div style={{ fontSize: 40 }}>⚡</div>
          <p style={{
            color: '#00d4ff',
            fontFamily: 'monospace',
            fontSize: 12,
            letterSpacing: 4
          }}>
            LOADING SOC DATA...
          </p>
        </div>
      )}

      {!loading && (
        <>
          {/* ── Stat Cards ─────────────────────────────── */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: 16,
            marginBottom: 24
          }}>
            {cards.map((c, i) => (
              <div key={i} style={{
                background: '#05051a',
                border: `1px solid ${c.color}33`,
                borderRadius: 10,
                padding: 20,
                boxShadow: `0 0 20px ${c.color}15`
              }}>
                <div style={{ fontSize: 28, marginBottom: 8 }}>{c.icon}</div>
                <div style={{
                  color: c.color,
                  fontSize: 32,
                  fontFamily: 'monospace',
                  fontWeight: 'bold',
                  textShadow: `0 0 15px ${c.color}88`
                }}>
                  {c.value ?? '—'}
                </div>
                <div style={{
                  color: '#444',
                  fontSize: 10,
                  fontFamily: 'monospace',
                  letterSpacing: 2,
                  marginTop: 6
                }}>
                  {c.label}
                </div>
              </div>
            ))}
          </div>

          {/* ── No Data State ───────────────────────────── */}
          {stats && stats.total_scanned === 0 && (
            <div style={{
              background: '#05051a',
              border: '1px solid #00d4ff22',
              borderRadius: 10,
              padding: 48,
              textAlign: 'center',
              marginBottom: 24
            }}>
              <div style={{ fontSize: 48, marginBottom: 16 }}>🔍</div>
              <p style={{
                color: '#00d4ff',
                fontFamily: 'monospace',
                fontWeight: 'bold',
                letterSpacing: 3,
                marginBottom: 8
              }}>
                NO SCANS YET
              </p>
              <p style={{ color: '#444', fontFamily: 'monospace', fontSize: 12 }}>
                Go to{' '}
                <Link to="/threats" style={{ color: '#00d4ff' }}>
                  Live Threats
                </Link>
                {' '}to analyze your first file
              </p>
            </div>
          )}

          {/* ── Threat Timeline ─────────────────────────── */}
          {stats && stats.total_scanned > 0 && (
            <div style={{
              background: '#05051a',
              border: '1px solid #00d4ff22',
              borderRadius: 10,
              padding: 24,
              marginBottom: 24
            }}>
              <h2 style={{
                color: '#00d4ff',
                fontFamily: 'monospace',
                fontSize: 12,
                letterSpacing: 3,
                margin: '0 0 20px'
              }}>
                📈 THREAT SCORE TIMELINE
              </h2>
              {stats.timeline && stats.timeline.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <LineChart data={[...stats.timeline].reverse()}>
                    <XAxis dataKey="time" hide />
                    <YAxis
                      domain={[0, 100]}
                      stroke="#1a1a2e"
                      tick={{ fill: '#444', fontSize: 10, fontFamily: 'monospace' }}
                    />
                    <Tooltip
                      contentStyle={{
                        background: '#05051a',
                        border: '1px solid #00d4ff33',
                        fontFamily: 'monospace',
                        fontSize: 11
                      }}
                      labelFormatter={() => 'Threat Score'}
                      formatter={(v) => [v.toFixed(1), 'Score']}
                    />
                    <Line
                      type="monotone"
                      dataKey="score"
                      stroke="#ff003c"
                      strokeWidth={2}
                      dot={false}
                      activeDot={{ r: 4, fill: '#ff003c' }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: 120,
                  color: '#333',
                  fontFamily: 'monospace',
                  fontSize: 12
                }}>
                  Not enough data for timeline yet
                </div>
              )}
            </div>
          )}

          {/* ── Recent Threats Table ─────────────────────── */}
          <div style={{
            background: '#05051a',
            border: '1px solid #00d4ff22',
            borderRadius: 10,
            padding: 24
          }}>
            <h2 style={{
              color: '#00d4ff',
              fontFamily: 'monospace',
              fontSize: 12,
              letterSpacing: 3,
              margin: '0 0 20px'
            }}>
              🔍 RECENT DETECTIONS
            </h2>
            <div style={{ overflowX: 'auto' }}>
              <table style={{
                width: '100%',
                borderCollapse: 'collapse',
                fontFamily: 'monospace',
                fontSize: 11
              }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #111' }}>
                    {['FILE', 'PREDICTION', 'SCORE', 'TIMESTAMP', 'HASH'].map(h => (
                      <th key={h} style={{
                        color: '#333',
                        textAlign: 'left',
                        padding: '8px 12px',
                        letterSpacing: 2,
                        fontWeight: 'normal'
                      }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {threats.length === 0 ? (
                    <tr>
                      <td colSpan={5} style={{
                        textAlign: 'center',
                        padding: 32,
                        color: '#333',
                        fontFamily: 'monospace'
                      }}>
                        No detections yet —{' '}
                        <Link to="/threats" style={{ color: '#00d4ff' }}>
                          run a scan
                        </Link>
                      </td>
                    </tr>
                  ) : threats.map((t, i) => {
                    const scoreColor =
                      t.threat_score > 70 ? '#ff003c' :
                      t.threat_score > 30 ? '#ff8c00' : '#00ff88'
                    const predColor =
                      t.prediction === 'Ransomware' ? '#ff003c' :
                      t.prediction === 'Suspicious'  ? '#ff8c00' : '#00ff88'

                    return (
                      <tr key={i} style={{ borderBottom: '1px solid #0a0a1a' }}
                        onMouseEnter={e => e.currentTarget.style.background = '#0d0d1a'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                        <td style={{ padding: '10px 12px', color: '#ccc' }}>
                          {t.file_name}
                        </td>
                        <td style={{ padding: '10px 12px', color: predColor, fontWeight: 'bold' }}>
                          {t.prediction}
                        </td>
                        <td style={{ padding: '10px 12px' }}>
                          <span style={{
                            color: scoreColor,
                            fontWeight: 'bold',
                            textShadow: `0 0 8px ${scoreColor}88`
                          }}>
                            {t.threat_score?.toFixed(1)}
                          </span>
                        </td>
                        <td style={{ padding: '10px 12px', color: '#444' }}>
                          {t.timestamp?.slice(0, 19).replace('T', ' ')}
                        </td>
                        <td style={{ padding: '10px 12px', color: '#2a2a3a', fontSize: 10 }}>
                          {t.blockchain_hash
                            ? t.blockchain_hash.slice(0, 14) + '...'
                            : '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}