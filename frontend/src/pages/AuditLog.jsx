import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { getAuditLogs } from '../api'

const ACTION_COLORS = {
  LOGIN_SUCCESS:    '#00ff88',
  LOGIN_FAILED:     '#ff003c',
  SCAN:             '#00d4ff',
  UPLOAD_SCAN:      '#a78bfa',
  REPORT_DOWNLOAD:  '#00d4ff',
  CSV_EXPORT:       '#00ff88',
  USER_CREATED:     '#ff8c00',
  USER_DELETED:     '#ff003c',
  PASSWORD_CHANGED: '#ff8c00',
  QUARANTINE_CLEARED: '#ff8c00',
  THREATS_CLEARED:  '#ff003c',
  SETTINGS_CHANGED: '#ff8c00',
}

const ACTION_ICONS = {
  LOGIN_SUCCESS:    '✅',
  LOGIN_FAILED:     '❌',
  SCAN:             '🔍',
  UPLOAD_SCAN:      '📤',
  REPORT_DOWNLOAD:  '📄',
  CSV_EXPORT:       '📥',
  USER_CREATED:     '👤',
  USER_DELETED:     '🗑️',
  PASSWORD_CHANGED: '🔑',
  QUARANTINE_CLEARED: '🗑️',
  THREATS_CLEARED:  '🗑️',
  SETTINGS_CHANGED: '⚙️',
}

export default function AuditLog() {
  const [logs,    setLogs]    = useState([])
  const [loading, setLoading] = useState(true)
  const [filter,  setFilter]  = useState('')
  const [user,    setUser]    = useState('')

  useEffect(() => {
    getAuditLogs()
      .then(r => setLogs(r.data))
      .catch(() => {})
      .finally(() => setLoading(false))
    const t = setInterval(() => {
      getAuditLogs().then(r => setLogs(r.data)).catch(() => {})
    }, 15000)
    return () => clearInterval(t)
  }, [])

  const filtered = logs.filter(l => {
    const matchAction = !filter || l.action.includes(filter.toUpperCase())
    const matchUser   = !user   || l.username?.toLowerCase().includes(user.toLowerCase())
    return matchAction && matchUser
  })

  // Summary counts
  const counts = logs.reduce((acc, l) => {
    acc[l.action] = (acc[l.action] || 0) + 1
    return acc
  }, {})

  const topActions = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)

  return (
    <div style={{ minHeight: '100vh', background: '#000010', padding: 24, fontFamily: 'monospace' }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 28, flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1 style={{ color: '#fff', fontSize: 20, fontWeight: 'bold', letterSpacing: 4, margin: '0 0 4px' }}>
            📋 AUDIT LOG
          </h1>
          <p style={{ color: '#444', fontSize: 11, margin: 0, letterSpacing: 2 }}>
            All platform activity — logins, scans, admin actions
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <Link to="/" style={{ padding: '8px 16px', fontSize: 11, letterSpacing: 2, background: 'transparent', border: '1px solid #00d4ff', borderRadius: 6, color: '#00d4ff', textDecoration: 'none' }}>
            ← DASHBOARD
          </Link>
        </div>
      </div>

      {/* Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 24 }}>
        <div style={{ background: '#05051a', border: '1px solid #00d4ff22', borderRadius: 10, padding: 16 }}>
          <div style={{ color: '#00d4ff', fontSize: 28, fontWeight: 'bold' }}>{logs.length}</div>
          <div style={{ color: '#444', fontSize: 10, letterSpacing: 2, marginTop: 4 }}>TOTAL EVENTS</div>
        </div>
        <div style={{ background: '#05051a', border: '1px solid #00ff8822', borderRadius: 10, padding: 16 }}>
          <div style={{ color: '#00ff88', fontSize: 28, fontWeight: 'bold' }}>
            {logs.filter(l => l.action === 'LOGIN_SUCCESS').length}
          </div>
          <div style={{ color: '#444', fontSize: 10, letterSpacing: 2, marginTop: 4 }}>LOGINS</div>
        </div>
        <div style={{ background: '#05051a', border: '1px solid #ff003c22', borderRadius: 10, padding: 16 }}>
          <div style={{ color: '#ff003c', fontSize: 28, fontWeight: 'bold' }}>
            {logs.filter(l => l.action === 'LOGIN_FAILED').length}
          </div>
          <div style={{ color: '#444', fontSize: 10, letterSpacing: 2, marginTop: 4 }}>FAILED LOGINS</div>
        </div>
        <div style={{ background: '#05051a', border: '1px solid #00d4ff22', borderRadius: 10, padding: 16 }}>
          <div style={{ color: '#00d4ff', fontSize: 28, fontWeight: 'bold' }}>
            {logs.filter(l => l.action === 'SCAN' || l.action === 'UPLOAD_SCAN').length}
          </div>
          <div style={{ color: '#444', fontSize: 10, letterSpacing: 2, marginTop: 4 }}>SCANS</div>
        </div>
        <div style={{ background: '#05051a', border: '1px solid #ff8c0022', borderRadius: 10, padding: 16 }}>
          <div style={{ color: '#ff8c00', fontSize: 28, fontWeight: 'bold' }}>
            {logs.filter(l => ['USER_CREATED','USER_DELETED','PASSWORD_CHANGED','SETTINGS_CHANGED'].includes(l.action)).length}
          </div>
          <div style={{ color: '#444', fontSize: 10, letterSpacing: 2, marginTop: 4 }}>ADMIN ACTIONS</div>
        </div>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        <div>
          <div style={{ color: '#444', fontSize: 10, letterSpacing: 2, marginBottom: 4 }}>FILTER BY ACTION</div>
          <select
            value={filter}
            onChange={e => setFilter(e.target.value)}
            style={{ background: '#05051a', color: '#00d4ff', border: '1px solid #00d4ff33', padding: '6px 12px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace' }}>
            <option value="">ALL ACTIONS</option>
            {Object.keys(ACTION_COLORS).map(a => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
        </div>
        <div>
          <div style={{ color: '#444', fontSize: 10, letterSpacing: 2, marginBottom: 4 }}>FILTER BY USER</div>
          <input
            value={user}
            onChange={e => setUser(e.target.value)}
            placeholder="username..."
            style={{ background: '#05051a', color: '#fff', border: '1px solid #00d4ff33', padding: '6px 12px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace', outline: 'none' }}
          />
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end' }}>
          <span style={{ color: '#444', fontSize: 11 }}>
            Showing <span style={{ color: '#00d4ff' }}>{filtered.length}</span> of {logs.length} events
          </span>
        </div>
      </div>

      {/* Log Table */}
      <div style={{ background: '#05051a', border: '1px solid #00d4ff22', borderRadius: 10, padding: 24 }}>
        {loading ? (
          <div style={{ textAlign: 'center', color: '#00d4ff', padding: 40, letterSpacing: 3 }}>LOADING AUDIT LOG...</div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign: 'center', color: '#333', padding: 40, fontSize: 12 }}>
            No events found {filter || user ? 'for this filter' : '— activity will appear here as you use the platform'}
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #111' }}>
                  {['#', 'TIMESTAMP', 'USER', 'ACTION', 'DETAILS'].map(h => (
                    <th key={h} style={{ color: '#333', textAlign: 'left', padding: '8px 12px', letterSpacing: 2, fontWeight: 'normal' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((log, i) => {
                  const color = ACTION_COLORS[log.action] || '#666'
                  const icon  = ACTION_ICONS[log.action]  || '•'
                  return (
                    <tr key={log.id}
                      style={{ borderBottom: '1px solid #0a0a1a', cursor: 'default' }}
                      onMouseEnter={e => e.currentTarget.style.background = '#0d0d1a'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                      <td style={{ padding: '8px 12px', color: '#333' }}>{log.id}</td>
                      <td style={{ padding: '8px 12px', color: '#444' }}>
                        {log.timestamp?.slice(0, 19).replace('T', ' ')}
                      </td>
                      <td style={{ padding: '8px 12px', color: '#00d4ff' }}>{log.username}</td>
                      <td style={{ padding: '8px 12px' }}>
                        <span style={{
                          color,
                          fontWeight: 'bold',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 6
                        }}>
                          <span>{icon}</span>
                          <span style={{ letterSpacing: 1 }}>{log.action}</span>
                        </span>
                      </td>
                      <td style={{ padding: '8px 12px', color: '#666', maxWidth: 300 }}>
                        {log.details}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
