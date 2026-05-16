import { create } from 'zustand'

const AUTH_KEY = 'crie-auth'

const stored = (() => {
  try {
    return JSON.parse(localStorage.getItem(AUTH_KEY) || 'null')
  } catch {
    return null
  }
})()

export const useAuthStore = create((set) => ({
  apiKey: stored?.apiKey || null,
  user: stored?.user || null,
  setAuth: (apiKey, user) => {
    const payload = { apiKey, user }
    localStorage.setItem(AUTH_KEY, JSON.stringify(payload))
    set(payload)
  },
  clearAuth: () => {
    localStorage.removeItem(AUTH_KEY)
    set({ apiKey: null, user: null })
  },
}))
