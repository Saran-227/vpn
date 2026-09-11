const API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
export async function getDashboard(signal){
  const r = await fetch(`${API}/api/dashboard`, {signal})
  if(!r.ok) throw new Error(`Dashboard API returned ${r.status}`)
  return r.json()
}
export { API }
