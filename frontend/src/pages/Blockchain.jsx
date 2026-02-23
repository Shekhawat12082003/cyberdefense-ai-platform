import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

export default function Blockchain() {
  const [logs,         setLogs]         = useState([])
  const [hashInput,    setHashInput]    = useState('')
  const [verifyResult, setVerifyResult] = useState(null)
  const [loading,      setLoading]      = useState(false)
  const [status,       setStatus]       = useState(null)

  const headers = {
    'Content-Type': 'application/json',
    Authorization:  `Bearer ${localStorage.getItem('token')}`
  }

  useEffect(() => {
    fetch('http://localhost:5000/api/blockchain/logs', { headers })
      .then(r => r.json()).then(setLogs).catch(() => {})
    fetch('http://localhost:5000/api/blockchain/status', { headers })
      .then(r => r.json()).then(setStatus).catch(() => {})
  }, [])

  const verifyHash = async () => {
    if (!hashInput.trim()) return
    setLoading(true)
    setVerifyResult(null)
    try {
      const res    = await fetch('http://localhost:5000/api/blockchain/verify', {
        method: 'POST', headers,
        body:   JSON.stringify({ hash: hashInput.trim() })
      })
      const result = await res.json()
      setVerifyResult(result)
    } catch {
      setVerifyResult({ verified: false, entry: null })
    } finally {
      setLoading(false)
    }
  }

  const refreshLogs = () => {
    fetch('http://localhost:5000/api/blockchain/logs', { headers })
      .then(r => r.json()).then(setLogs).catch(() => {})
  }

  return (
    <div className="min-h-screen bg-black cyber-grid p-6">

      {/* Header */}
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold neon-text-blue tracking-widest cursor">
            BLOCKCHAIN VERIFICATION
          </h1>
          <p className="text-xs text-gray-500 mt-1">Tamper-proof threat log — Core Testnet2</p>
        </div>
        <div className="flex gap-3">
          <button onClick={refreshLogs}
            className="px-4 py-2 text-xs border border-green-400 text-green-400 rounded hover:bg-green-400 hover:text-black transition">
            🔄 REFRESH
          </button>
          <Link to="/" className="px-4 py-2 text-xs border border-cyan-400 text-cyan-400 rounded hover:bg-cyan-400 hover:text-black transition">
            ← DASHBOARD
          </Link>
        </div>
      </div>

      {/* Status Banner */}
      {status && (
        <div className={`rounded-lg p-4 mb-6 bg-gray-950 ${status.mode === 'core_testnet2' ? 'glow-green' : 'glow-blue'}`}>
          <div className="flex justify-between items-center flex-wrap gap-3">
            <div>
              <div className={`text-sm font-bold tracking-widest ${status.mode === 'core_testnet2' ? 'text-green-400' : 'text-cyan-400'}`}>
                {status.mode === 'core_testnet2' ? '⛓ LIVE ON CORE TESTNET2' : '📝 LOCAL SIMULATION MODE'}
              </div>
              <div className="text-xs text-gray-500 mt-1">
                {status.mode === 'core_testnet2'
                  ? 'All threats logged to real blockchain'
                  : 'Configure .env to enable real blockchain logging'}
              </div>
            </div>
            {status.mode === 'core_testnet2' && (
              <div className="text-xs text-gray-400 space-y-1">
                <div>Contract : <span className="text-cyan-400 font-mono">{status.contract?.slice(0, 20)}...</span></div>
                <div>Wallet   : <span className="text-cyan-400 font-mono">{status.wallet?.slice(0, 20)}...</span></div>
                <div>Chain ID : <span className="text-cyan-400">{status.chain_id}</span></div>
              </div>
            )}
            {status.mode === 'core_testnet2' && (
              <a href={`https://scan.test2.btcs.network/address/${status.contract}`}
                target="_blank" rel="noreferrer"
                className="text-xs text-cyan-400 underline hover:text-white transition">
                🔗 View Contract ↗
              </a>
            )}
          </div>
        </div>
      )}

      {/* How it works */}
      <div className="glow-blue bg-gray-950 rounded-lg p-5 mb-6">
        <h2 className="neon-text-blue text-xs tracking-widest mb-4">HOW BLOCKCHAIN LOGGING WORKS</h2>
        <div className="grid grid-cols-4 gap-4 text-center text-xs">
          {[
            { icon: '🔍', label: 'File Scanned',    desc: 'AI analyzes PE features'  },
            { icon: '🔐', label: 'Hash Created',    desc: 'SHA-256 of alert data'     },
            { icon: '⛓',  label: 'Logged On-Chain', desc: 'Core Testnet2 TX'          },
            { icon: '✅', label: 'Verified',         desc: 'Tamper-proof forever'      },
          ].map((s, i) => (
            <div key={i} className="bg-black rounded p-3 cyber-card">
              <div className="text-2xl mb-1">{s.icon}</div>
              <div className="text-white font-bold">{s.label}</div>
              <div className="text-gray-500 mt-1">{s.desc}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">

        {/* Verify */}
        <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card">
          <h2 className="neon-text-blue text-sm tracking-widest mb-4">🔎 VERIFY HASH</h2>
          <label className="text-xs text-gray-400 tracking-widest">
            PASTE ALERT HASH FROM THREATS PAGE
          </label>
          <textarea
            rows={3}
            className="w-full mt-2 px-3 py-2 bg-black border border-gray-700 rounded text-white text-xs font-mono focus:outline-none focus:border-cyan-400 transition resize-none"
            placeholder="Paste alert hash here..."
            value={hashInput}
            onChange={e => setHashInput(e.target.value)}
          />
          <button
            onClick={verifyHash}
            disabled={loading || !hashInput.trim()}
            className="w-full mt-3 py-3 bg-cyan-400 text-black font-bold text-xs tracking-widest rounded hover:opacity-80 transition disabled:opacity-50">
            {loading ? '⏳ VERIFYING...' : '🔍 VERIFY INTEGRITY'}
          </button>

          {verifyResult && (
            <div className={`mt-4 p-4 rounded fade-in ${verifyResult.verified ? 'glow-green bg-green-950' : 'glow-red bg-red-950'}`}>
              <div className={`font-bold text-sm mb-3 ${verifyResult.verified ? 'text-green-400' : 'text-red-400'}`}>
                {verifyResult.verified
                  ? '✅ HASH VERIFIED — Not Tampered'
                  : '❌ HASH NOT FOUND — Possible Tampering'}
              </div>
              {verifyResult.verified && verifyResult.entry && (
                <div className="text-xs text-gray-400 space-y-2">
                  <div className="flex justify-between">
                    <span>Prediction</span>
                    <span className={verifyResult.entry.prediction === 'Ransomware' ? 'text-red-400 font-bold' : 'text-green-400 font-bold'}>
                      {verifyResult.entry.prediction}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Score</span>
                    <span className="text-white">{verifyResult.entry.threat_score}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Block</span>
                    <span className="text-cyan-400">#{verifyResult.entry.block || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Source</span>
                    <span className="text-cyan-400">{verifyResult.source}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Timestamp</span>
                    <span className="text-gray-300">{verifyResult.entry.timestamp?.slice(0, 19)}</span>
                  </div>
                  {verifyResult.entry.explorer && (
                    <a href={verifyResult.entry.explorer} target="_blank" rel="noreferrer"
                      className="text-cyan-400 underline hover:text-white block mt-2 transition">
                      🔗 View on Explorer ↗
                    </a>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card">
          <h2 className="neon-text-blue text-sm tracking-widest mb-4">📊 BLOCKCHAIN STATS</h2>
          <div className="space-y-3">
            <div className="bg-black rounded p-4 text-center cyber-card">
              <div className="text-4xl font-bold text-cyan-400"
                style={{ textShadow: '0 0 20px #00d4ff' }}>
                {logs.length}
              </div>
              <div className="text-xs text-gray-400 mt-1 tracking-widest">TOTAL ENTRIES</div>
            </div>
            <div className="bg-black rounded p-4 text-center cyber-card">
              <div className="text-4xl font-bold text-green-400"
                style={{ textShadow: '0 0 20px #00ff88' }}>
                {logs.filter(l => l.mode === 'core_testnet2').length}
              </div>
              <div className="text-xs text-gray-400 mt-1 tracking-widest">ON-CHAIN ENTRIES</div>
            </div>
            <div className="bg-black rounded p-4 text-center cyber-card">
              <div className="text-4xl font-bold text-red-500"
                style={{ textShadow: '0 0 20px #ff003c' }}>
                {logs.filter(l => l.prediction === 'Ransomware').length}
              </div>
              <div className="text-xs text-gray-400 mt-1 tracking-widest">RANSOMWARE LOGGED</div>
            </div>
          </div>
        </div>
      </div>

      {/* Log Table */}
      <div className="glow-blue bg-gray-950 rounded-lg p-6">
        <h2 className="neon-text-blue text-sm tracking-widest mb-4">
          📋 IMMUTABLE THREAT LOG
          <span className="ml-2 text-gray-600 text-xs font-normal">({logs.length} entries)</span>
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-gray-500 border-b border-gray-800">
                <th className="text-left py-2 pr-4">BLOCK</th>
                <th className="text-left py-2 pr-4">ALERT HASH</th>
                <th className="text-left py-2 pr-4">PREDICTION</th>
                <th className="text-left py-2 pr-4">SCORE</th>
                <th className="text-left py-2 pr-4">MODE</th>
                <th className="text-left py-2 pr-4">TIMESTAMP</th>
                <th className="text-left py-2">TX</th>
              </tr>
            </thead>
            <tbody>
              {logs.length === 0 && (
                <tr>
                  <td colSpan={7} className="text-center text-gray-600 py-10">
                    No entries yet — analyze a file on the Threats page
                  </td>
                </tr>
              )}
              {[...logs].reverse().map((log, i) => (
                <tr key={i} className="border-b border-gray-900 hover:bg-gray-900 transition">
                  <td className="py-2 pr-4 text-cyan-400 font-mono">#{log.block}</td>
                  <td className="py-2 pr-4">
                    <div className="flex items-center gap-2">
                      <span className="text-gray-500 font-mono">
                        {log.alert_hash?.slice(0, 14)}...
                      </span>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(log.alert_hash)
                          setHashInput(log.alert_hash)
                        }}
                        className="text-gray-700 hover:text-cyan-400 transition"
                        title="Copy hash to verify box">
                        📋
                      </button>
                    </div>
                  </td>
                  <td className={`py-2 pr-4 font-bold ${log.prediction === 'Ransomware' ? 'text-red-500' : 'text-green-400'}`}>
                    {log.prediction}
                  </td>
                  <td className="py-2 pr-4">
                    <span className={`font-bold ${log.threat_score > 70 ? 'text-red-500' : log.threat_score > 30 ? 'text-yellow-400' : 'text-green-400'}`}>
                      {log.threat_score}
                    </span>
                  </td>
                  <td className="py-2 pr-4">
                    <span className={`px-2 py-1 rounded text-xs ${log.mode === 'core_testnet2' ? 'bg-green-950 text-green-400' : 'bg-gray-800 text-gray-400'}`}>
                      {log.mode === 'core_testnet2' ? '⛓ ON-CHAIN' : '📝 LOCAL'}
                    </span>
                  </td>
                  <td className="py-2 pr-4 text-gray-400">{log.timestamp?.slice(0, 19)}</td>
                  <td className="py-2">
                    {log.explorer ? (
                      <a href={log.explorer} target="_blank" rel="noreferrer"
                        className="text-cyan-400 underline hover:text-white transition">
                        View ↗
                      </a>
                    ) : (
                      <span className="text-gray-700">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}