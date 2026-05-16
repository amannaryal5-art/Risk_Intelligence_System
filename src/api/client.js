import axios from 'axios'
import { useAuthStore } from '../store/authStore'
import { API_BASE } from '../lib/utils'

const client = axios.create({
  baseURL: API_BASE,
  timeout: 60000,
})

client.interceptors.request.use((config) => {
  const key = useAuthStore.getState().apiKey
  if (key) config.headers['X-API-Key'] = key
  return config
})

client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      useAuthStore.getState().clearAuth()
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  },
)

export default client
