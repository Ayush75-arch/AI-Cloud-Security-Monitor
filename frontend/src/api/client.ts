import axios from 'axios'

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8020'

export const apiClient = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// Response interceptor — unwrap data envelope
apiClient.interceptors.response.use(
  (res) => res,
  (err) => {
    const message = err.response?.data?.errors?.[0]?.message ?? err.message
    return Promise.reject(new Error(message))
  },
)
