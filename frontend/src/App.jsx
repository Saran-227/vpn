import React from 'react'
import { Routes, Route } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import About from './pages/About'
import { useDashboardData } from './hooks/useDashboardData'

export default function App() {
  const data = useDashboardData()

  return (
    <Routes>
      <Route
        path="/"
        element={
          <Dashboard
            {...data}
            theme="dark"
            toggleTheme={() => {}}
          />
        }
      />
      <Route
        path="/about"
        element={<About connection={data.connection} />}
      />
    </Routes>
  )
}
