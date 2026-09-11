import { Routes, Route } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import About from './pages/About'
import { useDashboardData } from './hooks/useDashboardData'

export default function App() {
  const dashboardData = useDashboardData()
  return (
    <Routes>
      <Route path="/" element={<Dashboard {...dashboardData} theme="dark" toggleTheme={() => {}} />} />
      <Route path="/about" element={<About connection={dashboardData.connection} mode={dashboardData.data?.mode ?? 'MOCK'} />} />
    </Routes>
  )
}
