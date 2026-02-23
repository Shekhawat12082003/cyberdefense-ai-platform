import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { predict } from '../api'
import io from 'socket.io-client'

const DEFAULTS = {
  Machine: 332, DebugSize: 0, DebugRVA: 0, MajorImageVersion: 0,
  MajorOSVersion: 4, ExportRVA: 0, ExportSize: 0, IatVRA: 8192,
  MajorLinkerVersion: 8, MinorLinkerVersion: 0, NumberOfSections: 3,
  SizeOfStackReserve: 1048576, DllCharacteristics: 34112,
  ResourceSize: 672, BitcoinAddresses: 0
}

const RANSOMWARE_SAMPLE = {
  Machine: 332, DebugSize: 0, DebugRVA: 0, MajorImageVersion: 0,
  MajorOSVersion: 4, ExportRVA: 0, ExportSize: 0, IatVRA: 0,
  MajorLinkerVersion: 8, MinorLinkerVersion: 0, NumberOfSections: 6,
  SizeOfStackReserve: 262144, DllCharacteristics: 0,
  ResourceSize: 0, BitcoinAddresses: 1
}

export default function Threats() {
  const [features, setFeatures] = useState(DEFAULTS)
  const [fileName, setFileName] = useState('suspicious_file.dll')
  const [result,   setResult]   = useState(null)
  const [loading,  setLoading]  = useState(false)
  const [alerts,   setAlerts]   = useState([])
  const [wsStatus, setWsStatus] = useState('connecting')
  const [scanLog,  setScanLog]  = useState([])

  useEffect(() => {
    const socket = io('http://localhost:5000', {
      transports: ['websocket', 'polling']
    })
    socket.on('connect',           ()     => setWsStatus('connected'))
    socket.on('disconnect',        ()     => setWsStatus('disconnected'))
    socket.on('connected',         ()     => setWsStatus('connected'))
    socket.on('high_threat_alert', (data) => {
      setAlerts(prev => [{ ...data, id: Date.now() }, ...prev].slice(0, 5))
      setScanLog(prev => [{
        time: new Date().toLocaleTimeString(),
        msg:  `🚨 HIGH THREAT: Score ${data.threat_score} — ${data.prediction}`,
        type: 'danger'
      }, ...prev].slice(0, 20))
    })
    socket.on('file_scanned', (data) => {
      setScanLog(prev => [{
        time: new Date().toLocaleTimeString(),
        msg:  `📁 Auto-scanned: ${data.file_name} → ${data.prediction} (${data.threat_score})`,
        type: data.threat_score > 70 ? 'danger' : 'info'
      }, ...prev].slice(0, 20))
    })
    return () => socket.disconnect()
  }, [])

  const handlePredict = async () => {
    setLoading(true)
    try {
      const res = await predict({ ...features, file_name: fileName })
      setResult(res.data)
      setScanLog(prev => [{
        time: new Date().toLocaleTimeString(),
        msg:  `🔍 Scanned: ${fileName} → ${res.data.prediction} (${res.data.threat_score})`,
        type: res.data.threat_score > 70 ? 'danger' : 'info'
      }, ...prev].slice(0, 20))
    } catch {
      alert('Prediction failed — is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  const sendTestAlert = async () => {
    await fetch('http://localhost:5000/api/test-alert', {
      method: 'POST',
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
    })
  }

  const downloadReport = async () => {
    if (!result) return
    const res  = await fetch('http://localhost:5000/api/report', {
      method:  'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization:  `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify(result)
    })
    const blob = await res.blob()
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `incident_report_${Date.now()}.pdf`
    a.click()
    URL.revokeObjectURL(url)
  }

  const getRiskColor  = (s) => s > 70 ? 'text-red-500'   : s > 30 ? 'text-yellow-400' : 'text-green-400'
  const getRiskBorder = (s) => s > 70 ? 'alert-pulse'     : s > 30 ? 'border border-yellow-400' : 'glow-green'
  const getRiskBg     = (s) => s > 70 ? 'bg-red-950'      : s > 30 ? 'bg-yellow-950'  : 'bg-green-950'

  return (
    <div className="min-h-screen bg-black cyber-grid p-6">

      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold neon-text-blue tracking-widest cursor">
            LIVE THREAT MONITOR
          </h1>
          <div className="flex items-center gap-3 mt-1">
            <div className={`w-2 h-2 rounded-full ${wsStatus === 'connected' ? 'bg-green-400' : 'bg-red-500'}`}
              style={{ boxShadow: wsStatus === 'connected' ? '0 0 8px #00ff88' : '0 0 8px #ff003c' }} />
            <span className="text-xs text-gray-500">
              WebSocket: <span className={wsStatus === 'connected' ? 'text-green-400' : 'text-red-500'}>
                {wsStatus.toUpperCase()}
              </span>
            </span>
            <span className="text-xs text-gray-600">|</span>
            <span className="text-xs text-gray-500">
              Auto-scan: <span className="text-green-400">ACTIVE</span>
            </span>
          </div>
        </div>
        <div className="flex gap-3">
          <button onClick={sendTestAlert}
            className="px-4 py-2 text-xs border border-red-500 text-red-500 rounded hover:bg-red-500 hover:text-black transition">
            🚨 TEST ALERT
          </button>
          <Link to="/" className="px-4 py-2 text-xs border border-cyan-400 text-cyan-400 rounded hover:bg-cyan-400 hover:text-black transition">
            ← DASHBOARD
          </Link>
        </div>
      </div>

      {/* Live Alerts Banner */}
      {alerts.length > 0 && (
        <div className="mb-6 fade-in">
          <h2 className="neon-text-red text-xs tracking-widest mb-2">🚨 LIVE ALERTS</h2>
          {alerts.map(a => (
            <div key={a.id} className="alert-pulse bg-red-950 rounded p-3 mb-2 text-xs flex justify-between items-center fade-in">
              <span className="neon-text-red font-bold animate-pulse">⚠ HIGH THREAT DETECTED</span>
              <span className="text-white font-bold">Score: {a.threat_score}</span>
              <span className="text-yellow-400">{a.prediction}</span>
              <span className="text-gray-400">{a.timestamp?.slice(0, 19)}</span>
              <button onClick={() => setAlerts(prev => prev.filter(x => x.id !== a.id))}
                className="text-gray-600 hover:text-white ml-2 text-lg">✕</button>
            </div>
          ))}
        </div>
      )}

      <div className="grid grid-cols-2 gap-6 mb-6">

        {/* Input Panel */}
        <div className="glow-blue bg-gray-950 rounded-lg p-6 cyber-card">
          <h2 className="neon-text-blue text-sm tracking-widest mb-4">📂 FILE ANALYSIS INPUT</h2>

          <div className="mb-4">
            <label className="text-xs text-gray-400 tracking-widest">FILE NAME</label>
            <input
              className="w-full mt-1 px-3 py-2 bg-black border border-gray-700 rounded text-white text-sm focus:outline-none focus:border-cyan-400 transition"
              value={fileName}
              onChange={e => setFileName(e.target.value)}
            />
          </div>

          <div className="grid grid-cols-2 gap-2 mb-4 max-h-64 overflow-y-auto pr-1">
            {Object.entries(features).map(([key, val]) => (
              <div key={key}>
                <label className="text-xs text-gray-500">{key}</label>
                <input
                  type="number"
                  className="w-full mt-1 px-2 py-1 bg-black border border-gray-800 rounded text-white text-xs focus:outline-none focus:border-cyan-400 transition"
                  value={val}
                  onChange={e => setFeatures(prev => ({ ...prev, [key]: Number(e.target.value) }))}
                />
              </div>
            ))}
          </div>

          <div className="flex gap-2 mb-4">
            <button
              onClick={() => { setFeatures(DEFAULTS); setFileName('benign_file.dll') }}
              className="flex-1 py-2 text-xs border border-green-400 text-green-400 rounded hover:bg-green-400 hover:text-black transition">
              ✅ LOAD BENIGN
            </button>
            <button
              onClick={() => { setFeatures(RANSOMWARE_SAMPLE); setFileName('ransomware.dll') }}
              className="flex-1 py-2 text-xs border border-red-500 text-red-500 rounded hover:bg-red-500 hover:text-black transition">
              ☠ LOAD RANSOMWARE
            </button>
          </div>

          <button onClick={handlePredict} disabled={loading}
            className="w-full py-3 bg-cyan-400 text-black font-bold tracking-widest rounded hover:opacity-80 transition disabled:opacity-50 relative overflow-hidden">
            {loading ? (
              <span className="flex items-center justify-center gap-2">
                <span className="animate-spin">⟳</span> ANALYZING...
              </span>
            ) : '🔍 ANALYZE FILE'}
            {loading && <div className="scan-line" />}
          </button>

          {/* Auto-scan info */}
          <div className="mt-4 bg-black rounded p-3 border border-gray-800">
            <div className="text-xs text-gray-400 mb-1 tracking-widest">👁️ AUTO-SCAN FOLDER</div>
            <div className="text-xs text-green-400 font-mono">backend\watched\</div>
            <div className="text-xs text-gray-600 mt-1">Drop any .dll or .exe to auto-scan</div>
          </div>
        </div>

        {/* Result Panel */}
        <div className={`bg-gray-950 rounded-lg p-6 cyber-card transition-all ${result ? getRiskBorder(result.threat_score) : 'glow-blue'}`}>
          <h2 className="neon-text-blue text-sm tracking-widest mb-4">📊 ANALYSIS RESULT</h2>

          {!result && (
            <div className="flex flex-col items-center justify-center h-64 text-gray-600 text-sm gap-3">
              <div className="text-5xl opacity-30">🔍</div>
              <p>Submit a file to see results</p>
              <p className="text-xs text-gray-700">or drop file in watched folder</p>
            </div>
          )}

          {result && (
            <div className="space-y-4 fade-in">

              {/* Score */}
              <div className={`text-center py-5 rounded-lg ${getRiskBg(result.threat_score)}`}>
                <div className={`text-7xl font-bold ${getRiskColor(result.threat_score)}`}
                  style={{ textShadow: result.threat_score > 70 ? '0 0 20px #ff003c' : result.threat_score > 30 ? '0 0 20px #ffaa00' : '0 0 20px #00ff88' }}>
                  {result.threat_score}
                </div>
                <div className="text-gray-400 text-xs mt-1 tracking-widest">THREAT SCORE / 100</div>
                <div className={`text-2xl font-bold mt-2 tracking-widest ${getRiskColor(result.threat_score)}`}>
                  {result.risk_level} RISK
                </div>
                <div className={`text-sm mt-1 ${getRiskColor(result.threat_score)}`}>
                  {result.prediction}
                </div>
              </div>

              {/* ML Bar */}
              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>🌲 Random Forest</span>
                  <span className="text-cyan-400">{result.ml_confidence}%</span>
                </div>
                <div className="w-full bg-gray-800 rounded h-2">
                  <div className="bg-cyan-400 h-2 rounded progress-bar transition-all"
                    style={{ width: `${Math.min(result.ml_confidence, 100)}%` }} />
                </div>
              </div>

              {/* DL Bar */}
              <div>
                <div className="flex justify-between text-xs text-gray-400 mb-1">
                  <span>🧠 Neural Network</span>
                  <span className="text-red-400">{result.dl_confidence}%</span>
                </div>
                <div className="w-full bg-gray-800 rounded h-2">
                  <div className="bg-red-500 h-2 rounded progress-bar transition-all"
                    style={{ width: `${Math.min(result.dl_confidence, 100)}%` }} />
                </div>
              </div>

              {/* Top Features */}
              <div className="bg-black rounded p-3">
                <div className="text-xs text-gray-400 mb-2 tracking-widest">TOP INDICATORS</div>
                {result.top_features?.map((f, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs py-1 border-b border-gray-900">
                    <span className="text-gray-600">{i + 1}.</span>
                    <span className="text-cyan-400">{f}</span>
                  </div>
                ))}
              </div>

              {/* Blockchain */}
              <div className="bg-black rounded p-3">
                <div className="text-xs text-gray-400 mb-2 tracking-widest">⛓ BLOCKCHAIN LOG</div>

                {result.blockchain?.alert_hash && (
                  <div className="mb-3">
                    <div className="text-xs text-gray-600 mb-1 tracking-widest">ALERT HASH — copy to verify:</div>
                    <div className="flex items-center gap-2 bg-gray-950 rounded p-2">
                      <div className="text-xs text-cyan-400 font-mono break-all flex-1 leading-relaxed">
                        {result.blockchain.alert_hash}
                      </div>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(result.blockchain.alert_hash)
                          alert('✅ Hash copied!')
                        }}
                        className="text-xs border border-gray-700 text-gray-400 px-2 py-1 rounded hover:text-white shrink-0 transition">
                        📋 COPY
                      </button>
                    </div>
                  </div>
                )}

                {result.blockchain?.explorer ? (
                  <a href={result.blockchain.explorer} target="_blank" rel="noreferrer"
                    className="text-xs text-cyan-400 underline hover:text-white transition block mb-2">
                    🔗 View TX on Core Testnet2 Explorer ↗
                  </a>
                ) : (
                  <span className="text-xs text-gray-600">
                    {result.blockchain?.mode === 'local_simulation'
                      ? '📝 Logged locally (simulation)'
                      : '⏳ Logging to blockchain...'}
                  </span>
                )}

                {result.blockchain?.block && (
                  <div className="text-xs text-gray-500 mt-1">
                    Block: <span className="text-cyan-400">#{result.blockchain.block}</span>
                    {result.blockchain?.tx_hash && (
                      <span className="text-gray-600 ml-2 font-mono">
                        TX: {result.blockchain.tx_hash.slice(0, 16)}...
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Download Report */}
              <button onClick={downloadReport}
                className="w-full py-3 bg-green-400 text-black font-bold tracking-widest rounded hover:opacity-80 transition">
                📄 DOWNLOAD INCIDENT REPORT
              </button>

            </div>
          )}
        </div>
      </div>

      {/* Live Activity Log */}
      <div className="glow-blue bg-gray-950 rounded-lg p-5">
        <h2 className="neon-text-blue text-xs tracking-widest mb-3">
          📡 LIVE ACTIVITY LOG
          <span className="ml-2 text-gray-600 font-normal">({scanLog.length} events)</span>
        </h2>
        <div className="max-h-40 overflow-y-auto space-y-1">
          {scanLog.length === 0 && (
            <div className="text-gray-700 text-xs py-2">
              No activity yet — analyze a file or drop one in the watched folder
            </div>
          )}
          {scanLog.map((log, i) => (
            <div key={i} className={`text-xs font-mono flex gap-3 py-1 border-b border-gray-900 fade-in ${log.type === 'danger' ? 'text-red-400' : 'text-gray-400'}`}>
              <span className="text-gray-600 shrink-0">{log.time}</span>
              <span>{log.msg}</span>
            </div>
          ))}
        </div>
      </div>

    </div>
  )
}