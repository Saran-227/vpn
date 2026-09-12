/**
 * useDashboardData.js — Frontend-independent data hook
 *
 * Returns hardcoded demo data immediately. No fetch, no WebSocket.
 * Components receive individual models as props — not a backend contract.
 *
 * TODO (backend adapter): When your friend's backend is ready:
 *   1. Create src/adapters/backendAdapter.js with mapVpnStatus(), mapMetrics(),
 *      mapSecurity(), mapEvents(), mapChartData() functions.
 *   2. Replace the static imports below with useEffect + fetch/WebSocket calls.
 *   3. Pass raw backend JSON through the adapter before setting state.
 *   4. The returned shape { vpnStatus, metrics, security, events, chartData,
 *      endpoints, connection } stays identical — no component changes needed.
 */

import {
  vpnStatus,
  metrics,
  security,
  events,
  chartData,
  endpoints,
} from '../data/mockData'

export function useDashboardData() {
  return {
    vpnStatus,
    metrics,
    security,
    events,
    chartData,
    endpoints,
    connection: 'MOCK',
  }
}
