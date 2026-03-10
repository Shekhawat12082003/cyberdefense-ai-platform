import { useState, useEffect, useRef } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import axios from 'axios'

const API = 'http://localhost:5000'

// ══════════════════════════════════════════════════════════
// TYPING INDICATOR
// ══════════════════════════════════════════════════════════
function TypingDots() {
  return (
    <div style={{ display: 'flex', gap: 4, padding: '10px 14px', alignItems: 'center' }}>
      {[0, 1, 2].map(i => (
        <div key={i} style={{
          width: 7, height: 7, borderRadius: '50%',
          background: '#00d4ff',
          animation: `dotBounce 1.2s ease-in-out infinite`,
          animationDelay: `${i * 0.2}s`
        }} />
      ))}
      <style>{`
        @keyframes dotBounce {
          0%, 80%, 100% { transform: scale(0.6); opacity: 0.3; }
          40%            { transform: scale(1);   opacity: 1;   }
        }
      `}</style>
    </div>
  )
}

// ══════════════════════════════════════════════════════════
// MAIN CHATBOT PAGE
// ══════════════════════════════════════════════════════════
export default function Chatbot() {
  const [messages, setMessages]   = useState([])
  const [input,    setInput]      = useState('')
  const [loading,  setLoading]    = useState(false)
  const [context,  setContext]    = useState(null)
  const bottomRef = useRef(null)
  const navigate  = useNavigate()

  const token    = localStorage.getItem('token')
  const username = localStorage.getItem('user')
  const role     = localStorage.getItem('role')

  const navBtn = (color = '#00d4ff') => ({
    padding: '7px 14px', fontSize: 10, fontFamily: 'monospace', letterSpacing: 2,
    background: 'transparent', border: `1px solid ${color}`, borderRadius: 5,
    color, cursor: 'pointer', textDecoration: 'none', display: 'inline-block'
  })

  // ── Load initial context ───────────────────────────────
  useEffect(() => {
    const load = async () => {
      try {
        const [stats, threats] = await Promise.all([
          axios.get(`${API}/api/stats`,   { headers: { Authorization: `Bearer ${token}` } }),
          axios.get(`${API}/api/threats`, { headers: { Authorization: `Bearer ${token}` } }),
        ])
        setContext({ stats: stats.data, threats: threats.data.slice(0, 5) })
      } catch {}
    }
    load()

    // Welcome message
    setMessages([{
      role: 'assistant',
      text: `Hello **${username}**! I'm your CyberDefense AI Security Analyst.\n\nI have access to your live threat data and can help you:\n- 🔍 Explain why a file was flagged\n- 📊 Analyze your current threat posture\n- 🛡️ Recommend incident response steps\n- ⛓️ Explain SHAP feature importances\n- 🚨 Summarize recent detections\n\nWhat would you like to know?`,
      time: new Date().toLocaleTimeString()
    }])
  }, [])

  // ── Auto scroll ────────────────────────────────────────
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  // ── Send message ───────────────────────────────────────
  const send = async () => {
    const text = input.trim()
    if (!text || loading) return

    const userMsg = { role: 'user', text, time: new Date().toLocaleTimeString() }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const res = await axios.post(
        `${API}/api/chat`,
        { message: text, context },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      setMessages(prev => [...prev, {
        role: 'assistant',
        text: res.data.reply,
        time: new Date().toLocaleTimeString()
      }])
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        text: '⚠️ Unable to reach the AI backend. Make sure the backend is running and OPENAI_API_KEY is set in `.env`.',
        time: new Date().toLocaleTimeString(),
        error: true
      }])
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
  }

  // ── Suggested prompts ──────────────────────────────────
  const suggestions = [
    'Summarize current threat status',
    'What files were most dangerous?',
    'Explain what SHAP values mean',
    'What should I do if a ransomware is detected?',
    'How does the AI model work?',
  ]

  // ── Render markdown-like bold ──────────────────────────
  const renderText = (text) => {
    const parts = text.split(/(\*\*[^*]+\*\*)/g)
    return parts.map((p, i) =>
      p.startsWith('**') && p.endsWith('**')
        ? <strong key={i} style={{ color: '#00d4ff' }}>{p.slice(2, -2)}</strong>
        : p.split('\n').map((line, j, arr) =>
            j < arr.length - 1 ? [line, <br key={`${i}-${j}`} />] : line
          )
    )
  }

  return (
    <div style={{ minHeight: '100vh', background: '#000010', display: 'flex', flexDirection: 'column' }}>

      {/* ── Header ─────────────────────────────────────── */}
      <div style={{
        padding: '16px 24px',
        borderBottom: '1px solid #0d0d2a',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div>
          <h1 style={{ color: '#fff', fontFamily: 'monospace', fontSize: 17, fontWeight: 'bold', letterSpacing: 4, margin: '0 0 3px' }}>
            🤖 AI SECURITY ANALYST
          </h1>
          <p style={{ color: '#444', fontFamily: 'monospace', fontSize: 10, letterSpacing: 3, margin: 0 }}>
            CONTEXT-AWARE THREAT INTELLIGENCE CHAT
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {context && (
            <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#00ff88', letterSpacing: 2,
              padding: '4px 10px', border: '1px solid #00ff8844', borderRadius: 4 }}>
              ● LIVE DATA LOADED
            </span>
          )}
          <Link to="/"         style={navBtn('#00d4ff')}>← DASHBOARD</Link>
          <Link to="/soc"      style={navBtn('#00ff88')}>🖥 SOC</Link>
          <Link to="/threats"  style={navBtn('#00d4ff')}>⚡ THREATS</Link>
        </div>
      </div>

      {/* ── Messages ───────────────────────────────────── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        {messages.map((m, i) => (
          <div key={i} style={{
            display: 'flex',
            justifyContent: m.role === 'user' ? 'flex-end' : 'flex-start',
          }}>
            {m.role === 'assistant' && (
              <div style={{ fontSize: 20, marginRight: 10, alignSelf: 'flex-end', marginBottom: 4 }}>🤖</div>
            )}
            <div style={{
              maxWidth: '72%',
              background: m.role === 'user'
                ? 'linear-gradient(135deg, #00d4ff22, #0055ff22)'
                : m.error ? '#ff003c11' : 'rgba(0,10,30,0.9)',
              border: `1px solid ${m.role === 'user' ? '#00d4ff44' : m.error ? '#ff003c44' : '#0d1a33'}`,
              borderRadius: m.role === 'user' ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
              padding: '12px 16px',
            }}>
              <div style={{
                fontFamily: 'monospace',
                fontSize: 13,
                color: m.role === 'user' ? '#00d4ff' : '#d0d8e8',
                lineHeight: 1.7,
                whiteSpace: 'pre-wrap'
              }}>
                {renderText(m.text)}
              </div>
              <div style={{ fontFamily: 'monospace', fontSize: 9, color: '#333', marginTop: 6, textAlign: 'right' }}>
                {m.time}
              </div>
            </div>
            {m.role === 'user' && (
              <div style={{ fontSize: 18, marginLeft: 10, alignSelf: 'flex-end', marginBottom: 4 }}>👤</div>
            )}
          </div>
        ))}

        {loading && (
          <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
            <div style={{ fontSize: 20, marginRight: 10, alignSelf: 'flex-end', marginBottom: 4 }}>🤖</div>
            <div style={{
              background: 'rgba(0,10,30,0.9)',
              border: '1px solid #0d1a33',
              borderRadius: '16px 16px 16px 4px',
            }}>
              <TypingDots />
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* ── Suggestions ────────────────────────────────── */}
      {messages.length <= 1 && (
        <div style={{ padding: '0 24px 12px', display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {suggestions.map((s, i) => (
            <button key={i} onClick={() => { setInput(s); }}
              style={{
                padding: '6px 12px', fontSize: 11, fontFamily: 'monospace', letterSpacing: 1,
                background: 'transparent', border: '1px solid #0d1a33', borderRadius: 20,
                color: '#555', cursor: 'pointer', transition: 'all 0.2s'
              }}
              onMouseEnter={e => { e.target.style.borderColor = '#00d4ff44'; e.target.style.color = '#00d4ff' }}
              onMouseLeave={e => { e.target.style.borderColor = '#0d1a33';   e.target.style.color = '#555'    }}
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* ── Input ──────────────────────────────────────── */}
      <div style={{
        padding: '12px 24px 20px',
        borderTop: '1px solid #0d0d2a',
        display: 'flex',
        gap: 10,
        alignItems: 'flex-end'
      }}>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          rows={2}
          placeholder="Ask about threats, SHAP values, incident response... (Enter to send, Shift+Enter for newline)"
          style={{
            flex: 1,
            background: '#000a1e',
            border: '1px solid #0d1a33',
            borderRadius: 10,
            padding: '10px 14px',
            fontFamily: 'monospace',
            fontSize: 13,
            color: '#fff',
            resize: 'none',
            outline: 'none',
            lineHeight: 1.5,
            transition: 'border 0.2s'
          }}
          onFocus={e  => e.target.style.borderColor = '#00d4ff44'}
          onBlur={e   => e.target.style.borderColor = '#0d1a33'}
        />
        <button
          onClick={send}
          disabled={!input.trim() || loading}
          style={{
            padding: '10px 20px',
            fontFamily: 'monospace',
            fontSize: 11,
            fontWeight: 'bold',
            letterSpacing: 2,
            background: input.trim() && !loading ? '#00d4ff' : '#0d1a33',
            border: 'none',
            borderRadius: 10,
            color: input.trim() && !loading ? '#000' : '#333',
            cursor: input.trim() && !loading ? 'pointer' : 'not-allowed',
            transition: 'all 0.2s',
            minWidth: 80,
            height: 62
          }}>
          {loading ? '...' : 'SEND ▶'}
        </button>
      </div>
    </div>
  )
}
