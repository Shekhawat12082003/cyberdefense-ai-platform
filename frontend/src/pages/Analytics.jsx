import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { getStats, getThreats } from '../api'
import {
  PieChart, Pie, Cell, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer
} from 'recharts'

const COLORS = ['#ff003c', '#00ff88']

export default function Analytics() {
  const [stats,   setStats]   = useState(null)
  const [threats, setThreats] = useState([])

  useEffect(() => {
    const load = async () => {
      try {
        const [s, t] = await Promise.all([getStats(), getThreats()])
        setStats(s.data)
        setThreats(t.data)
      } catch {}
    }
    load()
  }, [])

  const pieData = stats ? [
    { name: 'Ransomware', value: stats.active_threats },
    { name: 'Benign',     value: stats.total_scanned - stats.active_threats }
  ] : []

  // Score distribution buckets
  const buckets = { '0-30': 0, '31-70': 0, '71-100': 0 }
  threats.forEach(t => {
    if (t.threat_score <= 30)       buckets['0-30']++
    else if (t.threat_score <= 70)  buckets['31-70']++
    else                            buckets['71-100']++
  })
  const barData = Object.entries(buckets).map(([range, count]) => ({ range, count }))

  return (
    <div className="min-h-screen bg-black p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-2xl font-bold text-white tracking-widest">📊 ANALYTICS</h1>
        <Link to="/" className="px-4 py-2 text-xs border border-neon-blue text-neon-blue rounded hover:bg-neon-blue hover:text-black transition">
          ← DASHBOARD
        </Link>
      </div>

      {/* Stat Summary */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        {[
          { label: 'TOTAL SCANNED',    value: stats?.total_scanned    ?? 0, color: 'neon-blue'  },
          { label: 'THREATS DETECTED', value: stats?.active_threats   ?? 0, color: 'neon-red'   },
          { label: 'HIGH RISK',        value: stats?.high_risk_alerts ?? 0, color: 'neon-red'   },
        ].map((c, i) => (
          <div key={i} className={`glow-${c.color} bg-gray-950 rounded-lg p-5 text-center`}>
            <div className={`text-4xl font-bold text-${c.color}`}>{c.value}</div>
            <div className="text-xs text-gray-400 mt-1 tracking-widest">{c.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Pie Chart */}
        <div className="glow-blue bg-gray-950 rounded-lg p-6">
          <h2 className="text-neon-blue text-sm tracking-widest mb-4">🥧 SAFE vs THREAT</h2>
          {pieData.every(d => d.value === 0) ? (
            <div className="flex items-center justify-center h-48 text-gray-600 text-sm">No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={90}
                  dataKey="value" label={({ name, percent }) => `${name} ${(percent*100).toFixed(0)}%`}>
                  {pieData.map((_, i) => <Cell key={i} fill={COLORS[i]} />)}
                </Pie>
                <Tooltip contentStyle={{ background: '#111', border: '1px solid #00d4ff', fontSize: 12 }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Bar Chart — Score Distribution */}
        <div className="glow-blue bg-gray-950 rounded-lg p-6">
          <h2 className="text-neon-blue text-sm tracking-widest mb-4">📊 SCORE DISTRIBUTION</h2>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={barData}>
              <XAxis dataKey="range" stroke="#444" tick={{ fill: '#aaa', fontSize: 11 }} />
              <YAxis stroke="#444" tick={{ fill: '#aaa', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#111', border: '1px solid #00d4ff', fontSize: 12 }} />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {barData.map((entry, i) => (
                  <Cell key={i} fill={i === 0 ? '#00ff88' : i === 1 ? '#ffaa00' : '#ff003c'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Timeline */}
      <div className="glow-blue bg-gray-950 rounded-lg p-6">
        <h2 className="text-neon-blue text-sm tracking-widest mb-4">📋 ALL DETECTIONS</h2>
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="text-left py-2">#</th>
              <th className="text-left py-2">FILE</th>
              <th className="text-left py-2">PREDICTION</th>
              <th className="text-left py-2">SCORE</th>
              <th className="text-left py-2">TIME</th>
            </tr>
          </thead>
          <tbody>
            {threats.length === 0 && (
              <tr><td colSpan={5} className="text-center text-gray-600 py-8">No data — run predictions from Threats page</td></tr>
            )}
            {threats.map((t, i) => (
              <tr key={i} className="border-b border-gray-900 hover:bg-gray-900">
                <td className="py-2 text-gray-600">{i + 1}</td>
                <td className="py-2 text-white">{t.file_name}</td>
                <td className={`py-2 font-bold ${t.prediction === 'Ransomware' ? 'text-neon-red' : t.prediction === 'Suspicious' ? 'text-yellow-400' : 'text-neon-green'}`}>
                  {t.prediction}
                </td>
                <td className="py-2 text-white">{t.threat_score?.toFixed(1)}</td>
                <td className="py-2 text-gray-400">{t.timestamp?.slice(0, 19)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}