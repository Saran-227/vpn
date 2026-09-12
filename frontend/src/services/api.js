/**
 * api.js — stub (DLS mode, backend-independent)
 *
 * TODO (backend integration): Uncomment the implementation below and remove
 * the stub export. Set VITE_API_BASE_URL in .env to point at the FastAPI server.
 *
 *   const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
 *
 *   export async function getDashboard(signal) {
 *     const r = await fetch(`${API}/api/dashboard`, { signal })
 *     if (!r.ok) throw new Error(`Dashboard API returned ${r.status}`)
 *     return r.json()
 *   }
 *
 *   export { API }
 */

export async function getDashboard() {
  throw new Error('API not connected — running in DLS mock mode')
}
