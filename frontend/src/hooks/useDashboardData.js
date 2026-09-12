/**
 * useDashboardData.js — DLS version (backend-independent)
 *
 * Returns static mock data immediately. No fetch, no WebSocket.
 *
 * TODO (backend integration): Restore the original implementation that calls
 * getDashboard() from services/api.js and connectDashboardSocket() from
 * services/websocket.js. The returned shape { data, connection, error, retry }
 * is identical — Dashboard.jsx needs no changes.
 *
 * Original implementation preserved below as reference:
 *
 *   import { useCallback, useEffect, useState } from 'react'
 *   import { getDashboard } from '../services/api'
 *   import { connectDashboardSocket } from '../services/websocket'
 *
 *   export function useDashboardData() {
 *     const [data, setData] = useState(null)
 *     const [connection, setConnection] = useState('CONNECTING')
 *     const [error, setError] = useState('')
 *     const refresh = useCallback(async () => {
 *       try { setError(''); setData(await getDashboard()) }
 *       catch (e) { setError(e.message) }
 *     }, [])
 *     useEffect(() => {
 *       refresh()
 *       return connectDashboardSocket({
 *         onData: d => { setData(d); setError('') },
 *         onStatus: setConnection,
 *       })
 *     }, [refresh])
 *     return { data, connection, error, retry: refresh }
 *   }
 */

import { MOCK_DASHBOARD } from '../data/mockData'

export function useDashboardData() {
  return {
    data: MOCK_DASHBOARD,
    connection: 'MOCK',
    error: '',
    retry: () => {},
  }
}
