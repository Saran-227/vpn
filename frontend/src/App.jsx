import { Routes, Route } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import About from './pages/About'
import { useDashboardData } from './hooks/useDashboardData'

// TODO (backend integration): useDashboardData will automatically switch to
// live API + WebSocket data once services/api.js and services/websocket.js
// are restored. No changes needed here.

export default function App() {
  const { data, connection } = useDashboardData()
  return (
    <Routes>
      <Route path="/"      element={<Dashboard data={data} connection={connection} theme="dark" toggleTheme={() => {}} />} />
      <Route path="/about" element={<About connection={connection} mode={data?.mode ?? 'MOCK'} />} />
    </Routes>
  )
}
