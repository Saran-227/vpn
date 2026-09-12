import { Routes, Route } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import About from './pages/About'
import { useDashboardData } from './hooks/useDashboardData'

// TODO (backend adapter): useDashboardData will return live data once
// src/adapters/backendAdapter.js is implemented and wired into the hook.
// No changes needed here or in any component.

export default function App() {
  const { vpnStatus, metrics, security, events, chartData, endpoints, connection } = useDashboardData()
  return (
    <Routes>
      <Route
        path="/"
        element={
          <Dashboard
            vpnStatus={vpnStatus}
            metrics={metrics}
            security={security}
            events={events}
            chartData={chartData}
            endpoints={endpoints}
            connection={connection}
            theme="dark"
            toggleTheme={() => {}}
          />
        }
      />
      <Route
        path="/about"
        element={<About connection={connection} />}
      />
    </Routes>
  )
}
