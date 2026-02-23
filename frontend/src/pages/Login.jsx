import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../api'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)
  const navigate = useNavigate()

  // Always clear storage when login page loads
  // This ensures no stale token causes auto-skip
  useEffect(() => {
    localStorage.clear()
  }, [])

  const handleLogin = async () => {
    if (!username.trim() || !password.trim()) {
      setError('Please enter username and password')
      return
    }
    setLoading(true)
    setError('')
    try {
      const res = await login(username.trim(), password.trim())

      // Clear again before saving (belt and suspenders)
      localStorage.clear()
      localStorage.setItem('token', res.data.token)
      localStorage.setItem('role',  res.data.role)
      localStorage.setItem('user',  res.data.username)

      navigate('/', { replace: true })
    } catch (err) {
      const msg = err?.response?.data?.error || 'Invalid username or password'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#000010',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative',
      overflow: 'hidden'
    }}>

      {/* Grid background */}
      <div style={{
        position: 'absolute',
        inset: 0,
        opacity: 0.06,
        backgroundImage: `
          linear-gradient(#00d4ff 1px, transparent 1px),
          linear-gradient(90deg, #00d4ff 1px, transparent 1px)
        `,
        backgroundSize: '40px 40px'
      }} />

      {/* Glow orb */}
      <div style={{
        position: 'absolute',
        width: 500,
        height: 500,
        borderRadius: '50%',
        background: 'radial-gradient(circle, #00d4ff06 0%, transparent 70%)',
        pointerEvents: 'none'
      }} />

      {/* Card */}
      <div style={{
        position: 'relative',
        zIndex: 10,
        width: '100%',
        maxWidth: 420,
        padding: 40,
        background: 'rgba(5,5,26,0.97)',
        border: '1px solid #00d4ff33',
        borderRadius: 12,
        boxShadow: '0 0 60px #00d4ff18, 0 0 120px #00d4ff08'
      }}>

        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <div style={{ fontSize: 52, marginBottom: 10 }}>🛡️</div>
          <h1 style={{
            color: '#ffffff',
            fontFamily: 'monospace',
            fontSize: 22,
            fontWeight: 'bold',
            letterSpacing: 4,
            margin: '0 0 6px'
          }}>
            CYBERDEFENSE AI
          </h1>
          <p style={{
            color: '#00d4ff',
            fontFamily: 'monospace',
            fontSize: 10,
            letterSpacing: 3,
            margin: 0
          }}>
            ZERO-DAY RANSOMWARE PLATFORM
          </p>
          <div style={{
            height: 1,
            marginTop: 20,
            background: 'linear-gradient(90deg, transparent, #00d4ff55, transparent)'
          }} />
        </div>

        {/* Username */}
        <div style={{ marginBottom: 16 }}>
          <label style={{
            display: 'block',
            color: '#00d4ff',
            fontFamily: 'monospace',
            fontSize: 10,
            letterSpacing: 3,
            marginBottom: 8
          }}>
            USERNAME
          </label>
          <input
            style={{
              width: '100%',
              padding: '12px 16px',
              background: '#000',
              border: '1px solid #ffffff18',
              borderRadius: 6,
              color: '#fff',
              fontFamily: 'monospace',
              fontSize: 14,
              outline: 'none',
              boxSizing: 'border-box',
              transition: 'border-color 0.2s'
            }}
            placeholder="admin"
            value={username}
            onChange={e => setUsername(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleLogin()}
            onFocus={e  => e.target.style.borderColor = '#00d4ff66'}
            onBlur={e   => e.target.style.borderColor = '#ffffff18'}
            autoComplete="username"
            autoFocus
          />
        </div>

        {/* Password */}
        <div style={{ marginBottom: 20 }}>
          <label style={{
            display: 'block',
            color: '#00d4ff',
            fontFamily: 'monospace',
            fontSize: 10,
            letterSpacing: 3,
            marginBottom: 8
          }}>
            PASSWORD
          </label>
          <input
            type="password"
            style={{
              width: '100%',
              padding: '12px 16px',
              background: '#000',
              border: '1px solid #ffffff18',
              borderRadius: 6,
              color: '#fff',
              fontFamily: 'monospace',
              fontSize: 14,
              outline: 'none',
              boxSizing: 'border-box',
              transition: 'border-color 0.2s'
            }}
            placeholder="••••••••"
            value={password}
            onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleLogin()}
            onFocus={e  => e.target.style.borderColor = '#00d4ff66'}
            onBlur={e   => e.target.style.borderColor = '#ffffff18'}
            autoComplete="current-password"
          />
        </div>

        {/* Error */}
        {error && (
          <div style={{
            padding: '10px 16px',
            marginBottom: 16,
            background: '#ff003c12',
            border: '1px solid #ff003c44',
            borderRadius: 6,
            color: '#ff003c',
            fontFamily: 'monospace',
            fontSize: 12,
            textAlign: 'center'
          }}>
            ⚠️ {error}
          </div>
        )}

        {/* Button */}
        <button
          onClick={handleLogin}
          disabled={loading}
          style={{
            width: '100%',
            padding: '13px 0',
            background: loading ? '#00d4ff55' : '#00d4ff',
            border: 'none',
            borderRadius: 6,
            color: '#000010',
            fontFamily: 'monospace',
            fontSize: 13,
            fontWeight: 'bold',
            letterSpacing: 3,
            cursor: loading ? 'not-allowed' : 'pointer',
            transition: 'all 0.2s',
            boxShadow: loading ? 'none' : '0 0 20px #00d4ff44'
          }}
          onMouseEnter={e => { if (!loading) e.target.style.boxShadow = '0 0 35px #00d4ff88' }}
          onMouseLeave={e => { if (!loading) e.target.style.boxShadow = '0 0 20px #00d4ff44' }}
        >
          {loading ? '🔐 AUTHENTICATING...' : '⚡ ACCESS SYSTEM'}
        </button>

        {/* Hint */}
        <div style={{
          marginTop: 24,
          paddingTop: 20,
          borderTop: '1px solid #ffffff08',
          textAlign: 'center'
        }}>
          <p style={{
            color: '#2a2a3a',
            fontFamily: 'monospace',
            fontSize: 11,
            margin: 0,
            letterSpacing: 1
          }}>
            admin / admin123 &nbsp;·&nbsp; analyst / analyst123
          </p>
        </div>

      </div>
    </div>
  )
}