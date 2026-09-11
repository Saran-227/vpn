import Dashboard from './pages/Dashboard'
import { useDashboardData } from './hooks/useDashboardData'

export default function App() {
  const dashboardData = useDashboardData()
  return <Dashboard {...dashboardData} theme="dark" toggleTheme={() => {}} />
}
