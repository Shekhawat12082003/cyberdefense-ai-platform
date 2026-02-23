import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { getSHAP } from '../api'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

export default function SHAPPage() {
  const [shap, setShap] = useState([])

  useEffect(() => {
    getSHAP().then(res => {
      const data = Object.entries(res.data)
        .map(([feature, value]) => ({ feature, value: parseFloat(value.toFixed(4)) }))
        .sort((a, b) => b.value - a.value)
      setShap(data)
    }).catch(() => {})
  }, [])

  const maxVal = shap[0]?.value || 1

  return (
    <div className="min-h-screen bg-black p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-widest">🧠 EXPLAINABLE AI — SHAP</h1>
          <p className="text-xs text-gray-500 mt-1">Feature impact on ransomware detection model</p>
        </div>
        <Link to="/" className="px-4 py-2 text-xs border border-neon-blue text-neon-blue rounded hover:bg-neon-blue hover:text-black transition">
          ← DASHBOARD
        </Link>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Bar Chart */}
        <div className="glow-blue bg-gray-950 rounded-lg p-6">
          <h2 className="text-neon-blue text-sm tracking-widest mb-4">📊 MEAN SHAP VALUES</h2>
          <ResponsiveContainer width="100%" height={400}>
            <BarChart data={shap} layout="vertical">
              <XAxis type="number" stroke="#444" tick={{ fill: '#aaa', fontSize: 10 }} />
              <YAxis type="category" dataKey="feature" width={160}
                tick={{ fill: '#aaa', fontSize: 10 }} />
              <Tooltip contentStyle={{ background: '#111', border: '1px solid #00d4ff', fontSize: 11 }} />
              <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                {shap.map((_, i) => (
                  <Cell key={i} fill={i === 0 ? '#ff003c' : i < 3 ? '#ff6633' : '#00d4ff'} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Feature Cards */}
        <div className="glow-blue bg-gray-950 rounded-lg p-6">
          <h2 className="text-neon-blue text-sm tracking-widest mb-4">🔍 FEATURE BREAKDOWN</h2>
          <div className="space-y-3">
            {shap.map((item, i) => (
              <div key={i}>
                <div className="flex justify-between text-xs mb-1">
                  <span className={i === 0 ? 'text-neon-red font-bold' : 'text-gray-300'}>
                    {i + 1}. {item.feature}
                  </span>
                  <span className="text-gray-400">{item.value}</span>
                </div>
                <div className="w-full bg-gray-800 rounded h-1.5">
                  <div
                    className="h-1.5 rounded transition-all"
                    style={{
                      width: `${(item.value / maxVal) * 100}%`,
                      background: i === 0 ? '#ff003c' : i < 3 ? '#ff6633' : '#00d4ff'
                    }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Explanation */}
          <div className="mt-6 bg-black rounded p-4 text-xs text-gray-400 leading-relaxed">
            <p className="text-neon-blue font-bold mb-2">What is SHAP?</p>
            <p>SHAP (SHapley Additive exPlanations) measures how much each feature contributes to the model's prediction. Higher values mean the feature has more influence on detecting ransomware.</p>
            <p className="mt-2">🔴 <span className="text-neon-red">DllCharacteristics</span> is the strongest indicator — ransomware sets specific DLL security flags.</p>
          </div>
        </div>
      </div>
    </div>
  )
}