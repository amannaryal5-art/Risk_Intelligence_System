import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { ShieldCheck } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { getWhoAmI } from '../api/auth'
import { useAuthStore } from '../store/authStore'
import Spinner from '../components/ui/Spinner'

export default function Login() {
  const [apiKey, setApiKey] = useState('')
  const [connectedUser, setConnectedUser] = useState(null)
  const setAuth = useAuthStore((state) => state.setAuth)
  const navigate = useNavigate()

  const connect = useMutation({
    mutationFn: async () => {
      const previous = useAuthStore.getState().apiKey
      useAuthStore.setState({ apiKey })
      try {
        return await getWhoAmI()
      } finally {
        useAuthStore.setState({ apiKey: previous })
      }
    },
    onSuccess: (user) => {
      setConnectedUser(user)
      setAuth(apiKey, user)
      toast.success(`Connected as ${user.username}`)
      navigate('/')
    },
    onError: (error) => {
      setConnectedUser(null)
      toast.error(error.response?.data?.detail || 'Invalid API key')
    },
  })

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-[#050913] px-4">
      <div className="absolute inset-0 flex items-center justify-center">
        <div className="absolute h-52 w-52 rounded-full border border-cyan-500/30 animate-radar" />
        <div className="absolute h-52 w-52 rounded-full border border-blue-500/20 [animation-delay:0.8s] animate-radar" />
      </div>

      <div className="panel-elevated relative z-10 w-full max-w-md p-8">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-700/50 bg-cyan-500/10">
          <ShieldCheck className="h-8 w-8 text-cyan-400" />
        </div>
        <div className="mt-6 text-center">
          <h1 className="font-mono text-3xl font-bold text-slate-50">CRIE v3.0</h1>
          <p className="mt-2 text-sm text-slate-400">Risk Intelligence System command-and-control dashboard</p>
        </div>
        <div className="mt-8 space-y-4">
          <input className="field" type="password" placeholder="Enter X-API-Key" value={apiKey} onChange={(event) => setApiKey(event.target.value)} />
          {import.meta.env.DEV ? (
            <button
              type="button"
              className="text-xs text-slate-500 underline hover:text-slate-300"
              onClick={() => setApiKey('demo123')}
            >
              Use default dev key
            </button>
          ) : null}
          <button type="button" className="btn-primary w-full" disabled={!apiKey || connect.isPending} onClick={() => connect.mutate()}>
            {connect.isPending ? <Spinner /> : null}
            Connect
          </button>
          {connectedUser ? (
            <div className="rounded-xl border border-emerald-700/50 bg-emerald-950/30 px-4 py-3 text-sm text-emerald-200">
              Connected as {connectedUser.username} ({connectedUser.role})
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
