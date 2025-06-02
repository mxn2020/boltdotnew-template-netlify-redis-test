import { useState } from 'react'

const API = '/api'

function App() {
  const [view, setView] = useState<'landing' | 'login' | 'register' | 'profile'>('landing')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState(localStorage.getItem('token') || '')
  const [profile, setProfile] = useState<any>(null)
  const [error, setError] = useState('')

  const handleLogin = async () => {
    setError('')
    const res = await fetch(`${API}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    const data = await res.json()
    if (res.ok) {
      setToken(data.token)
      localStorage.setItem('token', data.token)
      setView('profile')
      fetchProfile(data.token)
    } else {
      setError(data.error || 'Login failed')
    }
  }

  const handleRegister = async () => {
    setError('')
    const res = await fetch(`${API}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    const data = await res.json()
    if (res.ok) {
      setView('login')
    } else {
      setError(data.error || 'Register failed')
    }
  }

  const fetchProfile = async (jwt?: string) => {
    setError('')
    const res = await fetch(`${API}/profile`, {
      headers: { Authorization: `Bearer ${jwt || token}` },
    })
    const data = await res.json()
    if (res.ok) {
      setProfile(data.profile)
    } else {
      setError(data.error || 'Could not fetch profile')
    }
  }

  const handleLogout = () => {
    setToken('')
    setProfile(null)
    localStorage.removeItem('token')
    setView('landing')
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded shadow-md w-full max-w-sm">
        {view === 'landing' && (
          <>
            <h1 className="text-2xl font-bold mb-4">Welcome</h1>
            <button className="btn" onClick={() => setView('login')}>Login</button>
            <button className="btn ml-2" onClick={() => setView('register')}>Register</button>
          </>
        )}
        {view === 'login' && (
          <>
            <h2 className="text-xl font-bold mb-2">Login</h2>
            <input className="input" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
            <input className="input mt-2" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
            <button className="btn mt-4" onClick={handleLogin}>Login</button>
            <button className="btn ml-2" onClick={() => setView('landing')}>Back</button>
            {error && <div className="text-red-500 mt-2">{error}</div>}
          </>
        )}
        {view === 'register' && (
          <>
            <h2 className="text-xl font-bold mb-2">Register</h2>
            <input className="input" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
            <input className="input mt-2" type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} />
            <button className="btn mt-4" onClick={handleRegister}>Register</button>
            <button className="btn ml-2" onClick={() => setView('landing')}>Back</button>
            {error && <div className="text-red-500 mt-2">{error}</div>}
          </>
        )}
        {view === 'profile' && profile && (
          <>
            <h2 className="text-xl font-bold mb-2">Profile</h2>
            <div className="mb-2">Username: {profile.username}</div>
            <button className="btn" onClick={handleLogout}>Logout</button>
          </>
        )}
        {view === 'profile' && !profile && (
          <>
            <button className="btn" onClick={() => fetchProfile()}>Load Profile</button>
            <button className="btn ml-2" onClick={handleLogout}>Logout</button>
            {error && <div className="text-red-500 mt-2">{error}</div>}
          </>
        )}
      </div>
      <style>{`
        .btn { background: #6366f1; color: white; padding: 0.5rem 1rem; border-radius: 0.25rem; border: none; margin-top: 0.5rem; cursor: pointer; }
        .btn:hover { background: #4f46e5; }
        .input { width: 100%; padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 0.25rem; }
      `}</style>
    </div>
  )
}

export default App
